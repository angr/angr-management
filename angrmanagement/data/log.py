import atexit
import logging
from datetime import datetime
from logging.handlers import QueueHandler, QueueListener
from multiprocessing import Queue
from typing import Optional

from angr.utils.mp import Initializer

from angrmanagement.config import Conf


class LogTimeStamp:
    """
    A Log timestamp with formatting
    """

    def __init__(self, unix_timestamp: int):
        """
        :param unix_time: The unix time the timestamp represents
        """
        self._ts = datetime.fromtimestamp(unix_timestamp)
        self._cache_key: Optional[str] = None
        self._cache_str: Optional[str] = None

    def __str__(self) -> str:
        """
        Return the timestamp as a formatted string
        """
        if Conf.log_timestamp_format != self._cache_key:
            self._cache_str = self._ts.strftime(Conf.log_timestamp_format)
        return self._cache_str


class LogRecord:
    """
    Stores a log record.
    """

    __slots__ = (
        "level",
        "timestamp",
        "source",
        "content",
    )

    def __init__(self, level, unix_timestamp, source, content):
        self.timestamp = LogTimeStamp(unix_timestamp)
        self.level = level
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


class AMQueueHandler(QueueHandler):
    """
    A logging QueueHandler that is of a different type than the default QueueHandler
    This allows checking isinstance to ensure the handler is what we desired
    """


def install_queue_handler(queue: Queue):
    """
    Install a queue handler using the given queue
    This function should work for both fork and spawn modes of multiprocessing
    Fork modes may already have the parent logger installed, spawn may not
    """
    if not any(isinstance(i, AMQueueHandler) for i in logging.root.handlers):
        logging.root.handlers.insert(0, AMQueueHandler(queue))


def initialize(*args, **kwargs) -> None:
    """
    Installs a LogDumpHandler and sets up forwarding from other processes to this one
    """
    queue = Queue()
    # Install queue handlers to the current process and all future subprocesses
    Initializer.get().register(install_queue_handler, queue)
    install_queue_handler(queue)
    # Install a listener which forwards log records to the LogDumpHandler
    listener = QueueListener(queue, LogDumpHandler(*args, **kwargs))
    atexit.register(listener.stop)
    listener.start()
