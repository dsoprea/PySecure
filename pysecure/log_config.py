from logging import getLogger, Formatter, DEBUG, WARNING, StreamHandler

from pysecure.config import IS_DEVELOPMENT

default_logger = getLogger()
default_logger.setLevel(DEBUG if IS_DEVELOPMENT else WARNING)

log_console = StreamHandler()
log_format = '%(name)-12s %(levelname)-7s %(message)s'
log_console.setFormatter(Formatter(log_format))
default_logger.addHandler(log_console)

