"""
Class to extend functionality of Python's ldap3 module.
"""

# System Imports.
import ldap3, re

# User Class Imports.
from .resources import logging
from .resources.config import config


# Initialize logging.
logger = logging.get_logger(__name__)


class SimpleLdap(object):
    """
    Extends ldap3 module to have server binding and authentication methods.
    """
    def __init__(self):
        self._ldap_connection = None
        self.config = config.copy()

    def __del__(self):
        self.unbind_server()

    def set_host(self, host):
        """
        Sets config host value.
        :param host: Desired host.
        """
        if re.match('ldaps://', host):
            self.config['host'] = host
        else:
            self.config['host'] += host
        logger.debug('Host value set to {0}'.format(self.config['host']))

    def set_master_account(self, master_dn, master_password, check_credentials=True, get_info='SCHEMA'):
        """
        Checks that dn and pass authenticates properly. If so, sets config master account values.
        :param master_dn: Dn of master account.
        :param master_password: Password of master account.
        :param check_credentials: Bool if credentials should be validated. Defaults to true.
        :return: Boolean indicating if config values were set.
        """
        if check_credentials:
            # Checking credentials. Slower but ensures master account is valid for given LDAP.
            auth_result = self.authenticate(dn=master_dn, password=master_password, get_info=get_info)
            if auth_result[0]:
                # Authenticated properly.
                self.config['master_dn'] = master_dn
                self.config['master_password'] = master_password
                return True
            else:
                # Failed to auth. Logs should show error.
                return False
        else:
            # Skipping credential check. Initializes library faster but is less safe.
            self.config['master_dn'] = master_dn
            self.config['master_password'] = master_password
            return True

    def set_search_base(self, search_base):
        """
        Sets search base.
        In method format so user does not have to access library config for basic functionality.
        :param search_base: The base DN to search.
        """
        self.config['search_base'] = search_base

    def bind_server(self, host=None, dn=None, password=None, timeout=None, get_info='SCHEMA'):
        """
        Binds the class to an ldap server with specified credentials.
        :param host: LDAP server address.
        :param dn: Full DN of the user to log in with.
        :param password: Login user password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :return: True | False
        """
        logger.debug('Attempting server bind.')

        # Define kwarg values.
        if host is None:
            host = self.config['host']
        if dn is None:
            dn = self.config['master_dn']
        if password is None:
            password = self.config['master_password']
        if timeout is None:
            timeout = int(self.config['connection_timeout'])

        try:
            server = ldap3.Server(host=host, connect_timeout=timeout, get_info=get_info)
            logger.debug('Server: {0}'.format(server))

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
            self.unbind_server()
            return False
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            logger.error('Connection to ldap server timed out.\n{0}'.format(e))
            self.unbind_server()
            return False
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            logger.warning('Username or Password is incorrect.')
            self.unbind_server()
            return False
        except Exception as e:
            logger.error(e, exc_info=True)
            self.unbind_server()
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


    def search(self, search_base=None, search_filter=None, attributes=None, timeout=None, search_scope='LEVEL'):
        """
        Searches for the users in the ldap server based on a filter and return specified attributes.
        Assumes ldap connection is already made.

        Note: To view all user attributes, pass the "attributes" as a string of "ALL_ATTRIBUTES".

        :param search_base: The base DN to search.
        :param search_filter: The LDAP filter to use when searching.
        :param attributes: A list of attributes to return | "ALL_ATTRIBUTES".
        :param timeout: Number of seconds to wait before timing out the search.
        :param search_scope: The scope in which to search in.
        :return: None - Nothing found | Response - The response from the ldap server
        """
        logger.debug('Attempting server search.')

        # Define kwarg values.
        if search_base is None:
            if self.config['search_base'] is '':
                logger.error('No search base set. Cancelling search.')
                return None
            else:
                search_base = self.config['search_base']
        if search_filter is None:
            if self.config['search_filter'] is '':
                logger.error('No search filter set. Cancelling search.')
                return None
            else:
                search_filter = self.config['search_filter']
        if attributes is None:
            attributes = self.config['attributes']
        elif attributes == 'ALL_ATTRIBUTES':
            attributes = ldap3.ALL_ATTRIBUTES
        if timeout is None:
            timeout = int(self.config['search_timeout'])

        if search_scope == "LEVEL":
            search_scope = ldap3.LEVEL
        elif search_scope == "BASE":
            search_scope = ldap3.BASE
        else:
            search_scope = ldap3.SUBTREE

        try:
            self._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                paged_size=1,
                attributes=attributes,
                time_limit=timeout,
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

    def authenticate(self, host=None, dn=None, password=None, timeout=None, get_info='SCHEMA'):
        """
        Authenticates a user with an ldap server.
        Accomplishes this by binding to prove user exists, then immediately unbinding.
        :param host: Ldap server address.
        :param dn: Full DN of the user to log in with.
        :param password: User's password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :return: Array - [Boolean - Authentication success, String - status_message]
        """
        logger.debug('Attempting user authentication.')

        # Define kwarg values.
        if host is None:
            host = self.config['host']
        if dn is None:
            dn = self.config['master_dn']
        if password is None:
            password = self.config['master_password']
        if timeout is None:
            timeout = int(self.config['connection_timeout'])

        login_status = 'Authentication success.'
        login_success = False
        try:
            server = ldap3.Server(host=host, connect_timeout=timeout, get_info=get_info)
            logger.debug('Server: {0}'.format(server))

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
            logger.error(e, exc_info=True)
            self.unbind_server()
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            login_status = 'Connection to ldap server timed out.'
            logger.error('{0}\n{1}'.format(login_status, e), exc_info=True)
            self.unbind_server()
        except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
            login_status = 'Username or Password is incorrect.'
            logger.warning(login_status)
            self.unbind_server()
        except Exception as e:
            login_status = 'An unknown error occurred, please see the log for more details.'
            logger.error(e, exc_info=True)
            self.unbind_server()

        return [login_success, login_status]

    def authenticate_with_uid(self, uid, pw, host=None, dn=None, password=None, search_base=None, search_filter=None,
                    conn_timeout=None, search_timeout=None, get_info='SCHEMA', is_cae_ldap=True):
        """
        First logs into server with known user. Then attempts to find user with given uid.
        On success, reads user values, disconnects and attempts authenticate function with user's full dn.
        :param uid: User UID to search for.
        :param pw: User password to attempt login with.
        :param host: Ldap server address.
        :param dn: Full DN of the a known user.
        :param password: Known user's password.
        :param search_base: The base user DN to search.
        :param search_filter: The LDAP filter to use when searching.
        :param conn_timeout: Number of seconds to wait before timing out the connection.
        :param search_timeout: Number of seconds to wait before timing out the search.
        :return: Array - [Boolean - Authentication success, String - status_message]
        """
        logger.debug('Attempting user authentication with specified UID.')

        # Define kwarg values.
        if host is None:
            host = self.config['host']
        if dn is None:
            dn = self.config['master_dn']
        if password is None:
            password = self.config['master_password']
        if search_base is None:
            if self.config['search_base'] is '':
                logger.error('No search base set. Cancelling search.')
                return None
            else:
                search_base = self.config['search_base']
        if search_filter is None:
            if self.config['search_filter'] is '':
                search_filter = '(uid={0})'.format(uid)
            else:
                search_filter = self.config['search_filter']
        if conn_timeout is None:
            conn_timeout = int(self.config['connection_timeout'])
        if search_timeout is None:
            search_timeout = int(self.config['search_timeout'])

        # Bind to server with known account.
        connection = self.bind_server(host, dn, password, conn_timeout, get_info=get_info)
        if connection:
            # Search for user with given UID.
            search_filter = search_filter.format(uid)
            if is_cae_ldap:
                results = self.search(search_base, search_filter, ['cn'], search_timeout)
            else:
                results = uid

            if results is not None:
                # UID found. Disconnect from known account and attempt login with found account.
                self.unbind_server()
                if is_cae_ldap:
                    user_dn = '{0}{1}'.format('cn={0},'.format(results['cn'][0]), search_base)
                else:
                    user_dn = '{0}{1}'.format('uid={0},'.format(results), search_base)
                results = self.authenticate(host, user_dn, pw, get_info=get_info)
                return results
            else:
                # Failed to find user with given uid.
                return [False, 'Failed to find user with given UID.']
        else:
            # Failed to connect to server.
            return [False, 'Failed to connect to ldap server.']
