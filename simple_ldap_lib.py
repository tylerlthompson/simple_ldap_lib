"""
Class to extend functionality of Python's ldap3 module.
"""

# System Imports.
import ldap3

# User Class Imports.
from resources import logging
from resources.config import config


# Initialize logging.
logger = logging.get_logger(__name__)


class SimpleLdap(object):
    """
    Extends ldap3 module to have server binding and authentication methods.
    """
    def __init__(self):
        self._ldap_connection = None

    def __del__(self):
        self.unbind_server()

    def bind_server(self, host=config['host'], dn=config['dn'], password=config['password'],
                    timeout=int(config['connection_timeout'])):
        """
        Binds the class to an ldap server with specified credentials.
        :param host: LDAP server address.
        :param dn: Full DN of the user to log in with.
        :param password: Login user password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :return: True | False
        """
        logger.debug('Attempting server bind.')
        try:
            server = ldap3.Server(host=host, connect_timeout=timeout)
            logger.debug('Server: {0}'.format(server))
            # NOTE: Connection errors out when using Server object. Only seems to work with direct host value.
            self._ldap_connection = ldap3.Connection(
                server=server,
                authentication=ldap3.SIMPLE,
                user=dn,
                password=password,
                raise_exceptions=True
            )
            logger.debug('Created connection: {0}'.format(self._ldap_connection))
            self._ldap_connection.bind()
            logger.debug('Bound connection: {0}'.format(self._ldap_connection))
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            logger.error('Failed to connect to ldap server.\n{0}'.format(e))
            return False
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            logger.error('Connection to ldap server timed out.\n{0}'.format(e))
            return False
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            logger.warning('Username or Password is incorrect.')
        except Exception as e:
            logger.error(e, exc_info=True)
            return False
        return True

    def unbind_server(self):
        """
        Attempts to unbind server.
        """
        try:
            if self._ldap_connection.bound:
                self._ldap_connection.unbind()
                logger.debug('Unbound connection: {0}'.format(self._ldap_connection))
        except AttributeError:
            pass

    def search(self, search_base=config['search_base'], search_filter=config['search_filter'],
               attributes=config['attributes'], timeout=int(config['search_timeout'])):
        """
        Searches for the users in the ldap server based on a filter and return specified attributes.
        Assumes ldap connection is already made.
        :param search_base: The base DN to search.
        :param search_filter: The LDAP filter to use when searching.
        :param attributes: A list of attributes to return.
        :param timeout: Number of seconds to wait before timing out the connection.
        :return: None - Nothing found | Response - The response from the ldap server
        """
        try:
            self._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=ldap3.LEVEL,
                paged_size=1,
                attributes=attributes,
                time_limit=timeout
            )
        except ldap3.core.exceptions.LDAPAdminLimitExceededResult:
            logger.error(self._ldap_connection.response)
        except Exception as e:
            logger.error(e, exc_info=True)
            return None

        # Query not found.
        if not self._ldap_connection.response:
            logger.error('No ldap response found.')
            return None

        return self._ldap_connection.response[0]['attributes']

    def authenticate(self, host=config['host'], dn=config['dn'], password=config['password'],
                    timeout=int(config['connection_timeout'])):
        """
        Authenticates a user with an ldap server.
        Accomplishes this by binding to prove user exists, then immediately unbinding.
        :param host: Ldap server address.
        :param dn: Full DN of the user to log in with.
        :param password: User's password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :return: Array - [Authentication success - True/False, status_message]
        """
        logger.debug('Attempting user authentication.')
        login_status = 'Authentication success.'
        login_success = False
        try:
            server = ldap3.Server(host=host, connect_timeout=timeout)
            logger.debug('Server: {0}'.format(server))
            # NOTE: Connection errors out when using Server object. Only seems to work with direct host value.
            self._ldap_connection = ldap3.Connection(
                server=server,
                authentication=ldap3.SIMPLE,
                user=dn,
                password=password,
                raise_exceptions=True
            )
            logger.debug('Created connection: {0}'.format(self._ldap_connection))
            self._ldap_connection.bind()
            logger.debug('Bound connection: {0}'.format(self._ldap_connection))
            self.unbind_server()
            login_success = True
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            login_status = 'Failed to connect to ldap server.'
            logger.error('{0}\n{1}'.format(login_status, e), exec_info=True)
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            login_status = 'Connection to ldap server timed out.'
            logger.error('{0}\n{1}'.format(login_status, e), exec_info=True)
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            login_status = 'Username or Password is incorrect.'
            logger.warning(login_status, exec_info=True)
        except Exception as e:
            login_status = 'An unknown error occurred, please see the log for more details.'
            logger.error(e, exc_info=True)

        return [login_success, login_status]
