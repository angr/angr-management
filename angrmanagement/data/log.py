import logging


class LogRecord:
    """
    Stores a log record.
    """

    __slots__ = ('level', 'timestamp', 'source', 'content', )

    def __init__(self, level, timestamp, source, content):
        self.level = level
        self.timestamp = timestamp
        self.source = source
        self.content = content


class LogDumpHandler(logging.Handler):
    """
    Dumps log messages.
    """

    def __init__(self, instance, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance = instance

    def emit(self, record: logging.LogRecord) -> None:
        log_record = LogRecord(record.levelno, record.created, record.name, self.format(record))
        self.instance.log.append(log_record)
        self.instance.log.am_event(log_record=log_record)
