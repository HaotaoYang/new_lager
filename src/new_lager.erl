%%%-------------------------------------------------------------------
%%% @doc
%%% user_defined log file
%%% @end
%%%-------------------------------------------------------------------

-module(new_lager).

-include_lib("lager/include/lager.hrl").

-behaviour(gen_event).

-export([
    init/1,
    handle_call/2,
    handle_event/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-export([config_to_id/1]).

-define(DEFAULT_LOG_PATH, "log/").
-define(DEFAULT_LOG_LEVEL, info).
-define(DEFAULT_ROTATION_SIZE, 10485760). %% 10mb
-define(DEFAULT_ROTATION_MOD, lager_rotator_default).
-define(DEFAULT_SYNC_LEVEL, error).
-define(DEFAULT_SYNC_INTERVAL, 1000).
-define(DEFAULT_SYNC_SIZE, 1024 * 64). %% 64kb
-define(DEFAULT_CHECK_INTERVAL, 1000).

-record(state, {
    name :: string(),
    level :: {'mask', integer()},
    fd :: file:io_device() | undefined,
    inode :: integer() | undefined,
    flap=false :: boolean(),
    size = 0 :: integer(),
    rotator = lager_util :: atom(),
    shaper :: lager_shaper(),
    formatter :: atom(),
    formatter_config :: any(),
    sync_on :: {'mask', integer()},
    check_interval = ?DEFAULT_CHECK_INTERVAL :: non_neg_integer(),
    sync_interval = ?DEFAULT_SYNC_INTERVAL :: non_neg_integer(),
    sync_size = ?DEFAULT_SYNC_SIZE :: non_neg_integer(),
    last_check = os:timestamp() :: erlang:timestamp(),
    cur_num
}).

-type option() :: {level, lager:log_level()} | {size, non_neg_integer()} | 
                  {rotator, atom()} | {high_water_mark, non_neg_integer()} |
                  {path, string()} | {sync_interval, non_neg_integer()} |
                  {sync_size, non_neg_integer()} | {sync_on, lager:log_level()} |
                  {check_interval, non_neg_integer()} | {formatter, atom()} |
                  {formatter_config, term()}.

-spec init([option(),...]) -> {ok, #state{}} | {error, {fatal,bad_config}}.
init(LogFileConfig) when is_list(LogFileConfig) ->
    case validate_logfile_proplist(LogFileConfig) of
        false ->
            %% falied to validate config
            {error, {fatal, bad_config}};
        Config ->
            %% probabably a better way to do this, but whatever
            [LogPath, Level, Size, Rotator, HighWaterMark, Flush, SyncInterval, SyncSize, SyncOn, CheckInterval, Formatter, FormatterConfig] =
            [proplists:get_value(Key, Config) || Key <- [path, level, size, rotator, high_water_mark, flush_queue, sync_interval, sync_size, sync_on, check_interval, formatter, formatter_config]],
            FlushThr = proplists:get_value(flush_threshold, Config, 0),
            {Y, M, D} = erlang:date(),
            FormatDate = lists:flatten(io_lib:format("~4..0w~2..0w~2..0w", [Y, M, D])),
            Name = LogPath ++ "log_" ++ FormatDate ++ ".log",
            schedule_rotation_timer(),
            Shaper = lager_util:maybe_flush(Flush, #lager_shaper{hwm = HighWaterMark, flush_threshold = FlushThr, id = Name}),
            State0 = #state{
                name = Name, level = Level, size = Size, rotator = Rotator, shaper = Shaper,
                formatter = Formatter, formatter_config = FormatterConfig, sync_on = SyncOn,
                sync_interval = SyncInterval, sync_size = SyncSize, check_interval = CheckInterval
            },
            State = case Rotator:create_logfile(Name, {SyncSize, SyncInterval}) of
                {ok, {FD, Inode, _}} ->
                    State0#state{fd = FD, inode = Inode};
                {error, Reason} ->
                    ?INT_LOG(error, "Failed to open log file ~s with error ~s", [Name, file:format_error(Reason)]),
                    State0#state{flap = true}
            end,
            {ok, State}
    end.

%% @private
handle_call({set_loglevel, Level}, #state{name = Name} = State) ->
    case validate_loglevel(Level) of
        false ->
            {ok, {error, bad_loglevel}, State};
        Levels ->
            ?INT_LOG(notice, "Changed loglevel of ~s to ~p", [Name, Level]),
            {ok, ok, State#state{level = Levels}}
    end;
handle_call(get_loglevel, #state{level = Level} = State) ->
    {ok, Level, State};
handle_call({set_loghwm, Hwm}, #state{shaper = Shaper, name = Name} = State) ->
    case validate_logfile_proplist([{high_water_mark, Hwm}]) of
        false ->
            {ok, {error, bad_log_hwm}, State};
        _ ->
            NewShaper = Shaper#lager_shaper{hwm = Hwm},
            ?INT_LOG(notice, "Changed loghwm of ~s to ~p", [Name, Hwm]),
            {ok, {last_loghwm, Shaper#lager_shaper.hwm}, State#state{shaper = NewShaper}}
    end;
% handle_call(rotate, State = #state{name = File}) ->
%     {ok, NewState} = handle_info({rotate, File}, State),
%     {ok, ok, NewState};
handle_call(_Request, State) ->
    {ok, ok, State}.

%% @private
handle_event({log, Message}, #state{name = Name, level = L, shaper = Shaper, formatter = Formatter, formatter_config = FormatConfig} = State) ->
    case lager_util:is_loggable(Message, L, {new_lager, Name}) of
        true ->
            case lager_util:check_hwm(Shaper) of
                {true, Drop, #lager_shaper{hwm = Hwm} = NewShaper} ->
                    NewState = case Drop > 0 of
                        true ->
                            Report = io_lib:format("lager_file_backend dropped ~p messages in the last second that exceeded the limit of ~p messages/sec", [Drop, Hwm]),
                            ReportMsg = lager_msg:new(Report, warning, [], []),
                            write(State, lager_msg:timestamp(ReportMsg), lager_msg:severity_as_int(ReportMsg), Formatter:format(ReportMsg, FormatConfig));
                        false ->
                            State
                    end,
                    {ok, write(NewState#state{shaper = NewShaper}, lager_msg:timestamp(Message), lager_msg:severity_as_int(Message), Formatter:format(Message, FormatConfig))};
                {false, _, NewShaper} ->
                    {ok, State#state{shaper = NewShaper}}
            end;
        false ->
            {ok, State}
    end;
handle_event(_Event, State) ->
    {ok, State}.

%% @private
handle_info(rotate_date, #state{fd = FD, name = File, rotator = Rotator, sync_interval = SyncInterval, sync_size = SyncSize} = State) ->
    {Y, M, D} = erlang:date(),
    FormatDate = lists:flatten(io_lib:format("~4..0w~2..0w~2..0w", [Y, M, D])),
    FileDir = filename:dirname(File),
    NewFile = FileDir ++ "/log_" ++ FormatDate ++ ".log",
    NewState = case Rotator:create_logfile(NewFile, {SyncSize, SyncInterval}) of
        {ok, {NewFD, Inode, _}} ->
            close_file(FD),
            State#state{fd = NewFD, name = NewFile, inode = Inode, cur_num = undefined};
        {error, Reason} ->
            ?INT_LOG(error, "Failed to open log file ~s with error ~s", [NewFile, file:format_error(Reason)]),
            State#state{flap = true}
    end,
    schedule_rotation_timer(),
    {ok, NewState};
handle_info({shaper_expired, Name}, #state{shaper = Shaper, name = Name, formatter = Formatter, formatter_config = FormatConfig} = State) ->
    case Shaper#lager_shaper.dropped of
        0 ->
            ok;
        Dropped ->
            Report = io_lib:format("lager_file_backend dropped ~p messages in the last second that exceeded the limit of ~p messages/sec", [Dropped, Shaper#lager_shaper.hwm]),
            ReportMsg = lager_msg:new(Report, warning, [], []),
            write(State, lager_msg:timestamp(ReportMsg), lager_msg:severity_as_int(ReportMsg), Formatter:format(ReportMsg, FormatConfig))
    end,
    {ok, State#state{shaper = Shaper#lager_shaper{dropped = 0, mps = 1, lasttime = os:timestamp()}}};
handle_info(_Info, State) ->
    {ok, State}.

%% @private
terminate(_Reason, #state{fd = FD}) ->
    %% leaving this function call unmatched makes dialyzer cranky
    _ = close_file(FD),
    ok.

%% @private
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Convert the config into a gen_event handler ID
config_to_id({Name,_Severity}) when is_list(Name) ->
    {?MODULE, Name};
config_to_id({Name,_Severity,_Size,_Rotation,_Count}) ->
    {?MODULE, Name};
config_to_id([{Name,_Severity,_Size,_Rotation,_Count}, _Format]) ->
    {?MODULE, Name};
config_to_id([{Name,_Severity}, _Format]) when is_list(Name) ->
    {?MODULE, Name};
config_to_id(_Config) -> {?MODULE, "new_file"}.

write(#state{name = Name, fd = FD, inode = Inode, flap = Flap, size = RotSize, rotator = Rotator, sync_interval = SyncInterval, sync_size = SyncSize, cur_num = CurNum} = State, Timestamp, Level, Msg) ->
    LastCheck = timer:now_diff(Timestamp, State#state.last_check) div 1000,
    case LastCheck >= State#state.check_interval orelse FD == undefined of
        true ->
            %% need to check for rotation
            CurFile = case CurNum of
                undefined -> Name;
                CurIndex -> Name ++ "." ++ integer_to_list(CurIndex)
            end,
            case Rotator:ensure_logfile(CurFile, FD, Inode, {State#state.sync_size, State#state.sync_interval}) of
                {ok, {_, _, Size}} when RotSize /= 0, Size > RotSize ->
                    {WriteFile, NewNum} = case CurNum of
                        undefined -> {Name ++ ".0", 0};
                        Index -> {Name ++ "." ++ integer_to_list(Index + 1), Index + 1}
                    end,
                    NewState = case Rotator:create_logfile(WriteFile, {SyncSize, SyncInterval}) of
                        {ok, {NewFD, NewInode, _}} ->
                            close_file(FD),
                            State#state{fd = NewFD, inode = NewInode, cur_num = NewNum};
                        {error, Reason} ->
                            ?INT_LOG(error, "Failed to open log file ~s with error ~s", [WriteFile, file:format_error(Reason)]),
                            State#state{flap = true}
                    end,
                    %% go around the loop again, we'll do another rotation check and hit the next clause of ensure_logfile
                    write(NewState, Timestamp, Level, Msg);
                {ok, {NewFD, NewInode, _}} ->
                    %% update our last check and try again
                    do_write(State#state{last_check = Timestamp, fd = NewFD, inode = NewInode}, Level, Msg);
                {error, Reason} ->
                    case Flap of
                        true ->
                            State;
                        _ ->
                            ?INT_LOG(error, "Failed to reopen log file ~s with error ~s", [Name, file:format_error(Reason)]),
                            State#state{flap=true}
                    end
            end;
        false ->
            do_write(State, Level, Msg)
    end.

do_write(#state{fd = FD, name = Name, flap = Flap} = State, Level, Msg) ->
    %% delayed_write doesn't report errors
    _ = file:write(FD, unicode:characters_to_binary(Msg)),
    {mask, SyncLevel} = State#state.sync_on,
    case (Level band SyncLevel) /= 0 of
        true ->
            %% force a sync on any message that matches the 'sync_on' bitmask
            Flap2 = case file:datasync(FD) of
                {error, Reason2} when Flap == false ->
                    ?INT_LOG(error, "Failed to write log message to file ~s: ~s", [Name, file:format_error(Reason2)]),
                    true;
                ok ->
                    false;
                _ ->
                    Flap
            end,
            State#state{flap = Flap2};
        _ ->
            State
    end.

validate_loglevel(Level) ->
    try lager_util:config_to_mask(Level) of
        Levels ->
            Levels
    catch
        _:_ ->
            false
    end.

validate_logfile_proplist(List) ->
    try validate_logfile_proplist(List, []) of
        Res ->
            %% merge with the default options
            lists:keymerge(1, lists:sort(Res), lists:sort([
                {path, ?DEFAULT_LOG_PATH},
                {level, validate_loglevel(?DEFAULT_LOG_LEVEL)},
                {size, ?DEFAULT_ROTATION_SIZE},
                {rotator, ?DEFAULT_ROTATION_MOD},
                {sync_on, validate_loglevel(?DEFAULT_SYNC_LEVEL)},
                {sync_interval, ?DEFAULT_SYNC_INTERVAL},
                {sync_size, ?DEFAULT_SYNC_SIZE},
                {check_interval, ?DEFAULT_CHECK_INTERVAL},
                {formatter, lager_default_formatter},
                {formatter_config, []}
            ]))
    catch
        {bad_config, Msg, Value} ->
            ?INT_LOG(error, "~s ~p for file ~p", [Msg, Value, proplists:get_value(file, List)]),
            false
    end.

validate_logfile_proplist([], Acc) ->
    Acc;
validate_logfile_proplist([{path, Path}|Tail], Acc) ->
    %% is there any reasonable validation we can do here?
    validate_logfile_proplist(Tail, [{path, Path}|Acc]);
validate_logfile_proplist([{level, Level}|Tail], Acc) ->
    case validate_loglevel(Level) of
        false ->
            throw({bad_config, "Invalid loglevel", Level});
        Res ->
            validate_logfile_proplist(Tail, [{level, Res}|Acc])
    end;
validate_logfile_proplist([{size, Size}|Tail], Acc) ->
    case Size of
        S when is_integer(S), S >= 0 ->
            validate_logfile_proplist(Tail, [{size, Size}|Acc]);
        _ ->
            throw({bad_config, "Invalid rotation size", Size})
    end;
validate_logfile_proplist([{rotator, Rotator}|Tail], Acc) ->
    case is_atom(Rotator) of
        true ->
            validate_logfile_proplist(Tail, [{rotator, Rotator}|Acc]);
        false ->
            throw({bad_config, "Invalid rotation module", Rotator})
    end;
validate_logfile_proplist([{high_water_mark, HighWaterMark}|Tail], Acc) ->
    case HighWaterMark of
        Hwm when is_integer(Hwm), Hwm >= 0 ->
            validate_logfile_proplist(Tail, [{high_water_mark, Hwm}|Acc]);
        _ ->
            throw({bad_config, "Invalid high water mark", HighWaterMark})
    end;
validate_logfile_proplist([{sync_interval, SyncInt}|Tail], Acc) ->
    case SyncInt of
        Val when is_integer(Val), Val >= 0 ->
            validate_logfile_proplist(Tail, [{sync_interval, Val}|Acc]);
        _ ->
            throw({bad_config, "Invalid sync interval", SyncInt})
    end;
validate_logfile_proplist([{sync_size, SyncSize}|Tail], Acc) ->
    case SyncSize of
        Val when is_integer(Val), Val >= 0 ->
            validate_logfile_proplist(Tail, [{sync_size, Val}|Acc]);
        _ ->
            throw({bad_config, "Invalid sync size", SyncSize})
    end;
validate_logfile_proplist([{check_interval, CheckInt}|Tail], Acc) ->
    case CheckInt of
        Val when is_integer(Val), Val >= 0 ->
            validate_logfile_proplist(Tail, [{check_interval, Val}|Acc]);
        always ->
            validate_logfile_proplist(Tail, [{check_interval, 0}|Acc]);
        _ ->
            throw({bad_config, "Invalid check interval", CheckInt})
    end;
validate_logfile_proplist([{sync_on, Level}|Tail], Acc) ->
    case validate_loglevel(Level) of
        false ->
            throw({bad_config, "Invalid sync on level", Level});
        Res ->
            validate_logfile_proplist(Tail, [{sync_on, Res}|Acc])
    end;
validate_logfile_proplist([{formatter, Fmt}|Tail], Acc) ->
    case is_atom(Fmt) of
        true ->
            validate_logfile_proplist(Tail, [{formatter, Fmt}|Acc]);
        false ->
            throw({bad_config, "Invalid formatter module", Fmt})
    end;
validate_logfile_proplist([{formatter_config, FmtCfg}|Tail], Acc) ->
    case is_list(FmtCfg) of
        true ->
            validate_logfile_proplist(Tail, [{formatter_config, FmtCfg}|Acc]);
        false ->
            throw({bad_config, "Invalid formatter config", FmtCfg})
    end;
validate_logfile_proplist([{flush_queue, FlushCfg}|Tail], Acc) ->
    case is_boolean(FlushCfg) of
        true ->
            validate_logfile_proplist(Tail, [{flush_queue, FlushCfg}|Acc]);
        false ->
            throw({bad_config, "Invalid queue flush flag", FlushCfg})
    end;
validate_logfile_proplist([{flush_queue_threshold, Thr}|Tail], Acc) ->
    case Thr of
        _ when is_integer(Thr), Thr >= 0 ->
            validate_logfile_proplist(Tail, [{flush_queue_threshold, Thr}|Acc]);
        _ ->
            throw({bad_config, "Invalid queue flush threshold", Thr})
    end;
validate_logfile_proplist([Other|_Tail], _Acc) ->
    throw({bad_config, "Invalid option", Other}).

schedule_rotation_timer() ->
    erlang:send_after(lager_util:calculate_next_rotation([{hour, 0}]) * 1000, self(), rotate_date),
    ok.

close_file(undefined) ->
    ok;
close_file(FD) ->
    %% Flush and close any file handles.
    _ = file:datasync(FD),
    _ = file:close(FD),
    ok.
