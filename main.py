"""
Mostly used to manually test library.

Library itself is located in "simple_ldap_lib.py" and "resources/config.py".
"""

# System Imports.
from getpass import getpass

# User Class Imports.
import resources.logging
import simple_ldap_lib


# Initialize logging.
logger = resources.logging.get_logger(__name__)


if __name__ == "__main__":
    logger.info('Starting Simple Ldap Lib.')
    ldap_lib = simple_ldap_lib.SimpleLdap()

    # # Get username and password from console prompt.
    username = input('Ldap DN: ')
    password = getpass('Password: ')

    # # Attempt authentication.
    # results = ldap_lib.authenticate()
    # logger.info('Authentication Results: {0}'.format(results))
    #
    # # Connect to server.
    # ldap_lib.bind_server()
    # # ldap_lib.bind_server(dn=username, password=password)
    #
    # # Search for values.
    # logger.info('')
    # logger.info('Attempting search...')
    # results = ldap_lib.search()
    # logger.info('Search results: {0}'.format(results))

    # Attempt authentication with uid.
    results = ldap_lib.authenticate_with_uid(username, password)
    logger.info('Auth with UID Results: {0}'.format(results))

    # Close program.
    logger.info('')
    logger.info('Terminating Program.')
