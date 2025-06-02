import win32evtlog


def monitor_security_log():
    log_handle = win32evtlog.OpenEventLog(None, "Security")

    try:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(log_handle, flags, 0)

        for event in events:
            print(f"Event ID: {event.EventID}, Source: {event.SourceName}")
            print(f"Record Number: {event.RecordNumber}")
            print(f"Time Generated: {event.TimeGenerated}")
            print(f"Event Data: {event.StringInserts}")
            print("-" * 50)

    finally:
        win32evtlog.CloseEventLog(log_handle)

if __name__ == "__main__":
    monitor_security_log()