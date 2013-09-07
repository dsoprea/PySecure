from logging import getLogger, Formatter, DEBUG, WARNING, StreamHandler

default_logger = getLogger()
default_logger.setLevel(WARNING)

log_console = StreamHandler()
log_format = '%(name)-12s %(levelname)-7s %(message)s'
log_console.setFormatter(Formatter(log_format))
default_logger.addHandler(log_console)

