new_lager
=====

    It provides an user-defined handler to rotate the log files everyday base on the lager project.

Examplle
-----

    1. configurate in rebar.config file:
    {parse_transform, lager_transform}

    2. configurate in sys.config file:
	[
		{lager, [
            {log_root, "log/"},
            {colored, true},

            {async_threshold, 5000},
            {async_threshold_window, 500},
            {error_logger_flush_queue, true},
            {error_logger_flush_threshold, 1000},
            {error_logger_hwm, 200},

            {crash_log, "log/crash.log"},
            {crash_log_msg_size, 65536},
            {crash_log_size, 10485760},
            {crash_log_date, "$D0"},
            {crash_log_count, 30},

            {handlers, [
				{lager_console_backend, [
					{level, debug},
					{formatter_config, [time, color, " [", severity, "] ", module, ":", function, ":", line, " ", message, "\e[0m\r\n"]}
				]},
				{lager_file_backend, [
					{level, debug},
					{formatter_config, [date, " ", time, " [", severity, "] ", module, ":", function, ":", line, " ", message, "\n"]},
					{file, "log/console.log"},
					{size, 10485760},
					{date, "$D0"},
					{count, 20}
				]},
				{lager_file_backend, [
					{level, error},
					{formatter_config, [date, " ", time, " [", severity, "] ", module, ":", function, ":", line, " ", message, "\n"]},
					{file, "log/error.log"},
					{size, 10485760},
					{date, "$D0"}
				]},
				{new_lager, [
					{level, debug},
					{formatter_config, [date, " ", time, " [", severity, "] ", module, ":", function, ":", line, " ", message, "\n"]},
					{path, "log/"}
				]}
			]}
		]}
	].

    3. add new_lager to xxx.app.src file:
    {applications, [
        kernel,
        stdlib,
        sasl,
        ssl,
        crypto,
        parse_trans,
        new_lager
    ]}

    4. include lib_hrl file:
    -include_lib("new_lager/include/log.hrl").
