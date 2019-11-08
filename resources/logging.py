"""
Logging initialization.

Note: Standard log priority is "NOTSET" > "DEBUG" > "INFO" > "WARNING" > "ERROR" > "CRITICAL".
"""

# System Imports.
import logging.config, os


# Statement to help library determine how to run logging.
simple_ldap_lib_logger = True


def get_logger(caller):
    """
    Returns an instance of the logger. Always pass the __name__ attribute.
    By calling through here, guarantees that logger will always have proper settings loaded.
    :param caller: __name__ attribute of caller.
    :return: Instance of logger, associated with caller's __name__.
    """
    # Initialize logger.
    _initialize_logger_settings()

    # Return logger instance, using passed name.
    return logging.getLogger(caller)


def _initialize_logger_settings(debug=False):
    """
    Creates log directories (if not found) and initializes logging settings.
    :param debug: Boolean to indicate if test log messages should also be displayed after initialization.
    """
    # Determine logging path.
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_dir = os.path.join(project_dir, 'resources/logs')

    # Check if logging path exists.
    if not os.path.exists(log_dir):
        print('Creating logging folders at "{0}".'.format(log_dir))
        os.makedirs(log_dir)

    # Load dictionary of settings into logger.
    logging.config.dictConfig(_create_logging_dict(log_dir))

    # Optionally test that logging is working as expected.
    if debug:
        logger = logging.getLogger(__name__)
        logger.info('Logging initialized.')
        logger.debug('Logging directory: {0}'.format(log_dir))


def _create_logging_dict(log_directory):
    """
    Creates dictionary-styled logging options.
    :param log_directory: Directory to use for saving logs.
    :return: Dictionary of logging options.
    """
    return {
        'version': 1,
        'formatters': {
            # Minimal logging. Only includes message.
            'minimal': {
                'format': '%(message)s',
            },
            # Simple logging. Includes message type and actual message.
            'simple': {
                'format': '[%(levelname)s] [%(filename)s %(lineno)d]: %(message)s',
            },
            # Basic logging. Includes date, message type, file originated, and actual message.
            'standard': {
                'format': '%(asctime)s [%(levelname)s] [%(filename)s %(lineno)d]: %(message)s',
            },
            # Verbose logging. Includes standard plus the process number and thread id.
            'verbose': {
                'format': '%(asctime)s [%(levelname)s] [%(filename)s %(lineno)d] || %(process)d %(thread)d || %(message)s',
            },
        },
        'handlers': {
            # Sends log message to the void. May be useful for debugging.
            'null': {
                'class': 'logging.NullHandler',
            },
            # To console.
            'console': {
                'level': 'INFO',
                'class': 'logging.StreamHandler',
                'formatter': 'simple',
            },
            # Debug Level - To file.
            'file_debug': {
                'level': 'DEBUG',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(log_directory, 'debug.log'),
                'maxBytes': 1024 * 1024 * 10,
                'backupCount': 10,
                'formatter': 'standard',
            },
            # Info Level - To file.
            'file_info': {
                'level': 'INFO',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(log_directory, 'info.log'),
                'maxBytes': 1024 * 1024 * 10,
                'backupCount': 10,
                'formatter': 'standard',
            },
            # Warn Level - To file.
            'file_warn': {
                'level': 'WARNING',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(log_directory, 'warn.log'),
                'maxBytes': 1024 * 1024 * 10,
                'backupCount': 10,
                'formatter': 'verbose',
            },
            # Error Level - To file.
            'file_error': {
                'level': 'ERROR',
                'class': 'logging.handlers.RotatingFileHandler',
                'filename': os.path.join(log_directory, 'error.log'),
                'maxBytes': 1024 * 1024 * 10,
                'backupCount': 10,
                'formatter': 'verbose',
            },
        },
        'loggers': {
            # All basic logging.
            '': {
                'handlers': ['console', 'file_debug', 'file_info', 'file_warn', 'file_error',],
                'level': 'NOTSET',
                'propagate': False,
            }
        },
    }
