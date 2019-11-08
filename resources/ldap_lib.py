"""
Class to extend functionality of Python's ldap3 module.
"""

# System Imports.
import ldap3, re

# User Class Imports.
from .config import config


# Initialize logging.
# Since this is a library, we specifically only modify logging if the library is being run alone.
try:
    # First, try to import the variable specific to our library logging.
    from SimpleLdapLib.resources.logging import simple_ldap_lib_logger

    # It worked, so we know the project is being run stand alone, probably as a unittest.
    # Proceed to configure logging.
    from SimpleLdapLib.resources.logging import get_logger as init_logging
    logger = init_logging(__name__)
except ModuleNotFoundError:
    # Above import failed. Project is being run as a library.
    # Just import existing logger and do not modify.
    import logging as init_logging
    logger = init_logging.getLogger('simple_ldap_lib')


class SimpleLdap(object):
    """
    Extends ldap3 module to have server binding and authentication methods.
    """
    def __init__(self, debug=False):
        self._ldap_connection = None
        self.config = config.copy()
        self.debug = debug

        if debug:
            logger.info('Running in debug mode. Will print out function args to console.')
            logger.info('Note that, for security reasons, password values will not be logged/displayed.')

    def __del__(self):
        self.unbind_server()

    def set_host(self, host):
        """
        Sets config host value.
        :param host: Desired host.
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling set_host().')
            logger.info('host: {0}')

        # Set host value.
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
        :param get_info: String indicating how to pull schema on connection.
        :return: Boolean indicating if config values were set.
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling set_master_account().')
            logger.info('master_dn: {0}'.format(master_dn))
            logger.info('check_credentials: {0}'.format(check_credentials))
            logger.info('get_info: {0}'.format(get_info))

        # Set account values.
        if check_credentials:
            # Checking credentials. Slower but ensures master account is valid for given LDAP.
            auth_result = self.authenticate_with_known_uid(dn=master_dn, password=master_password, get_info=get_info)
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
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling set_search_base().')
            logger.info('search_base: {0}'.format(search_base))

        # Set search base value.
        self.config['search_base'] = search_base

    def set_uid_attribute(self, uid_attribute):
        """
        Sets the user id to identify users with.
        Defaults to ['cn'], unless config value is set or this method is called.
        :param uid_attribute: Uid value to identify users with.
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling set_uid_attribute().')
            logger.info('uid_attribute: {0}'.format(uid_attribute))

        # Set uid value.
        if isinstance(uid_attribute, str):
            self.config['default_uid'] = uid_attribute
        else:
            raise TypeError('uid_attribute must be a string.')

    def bind_server(self, host=None, dn=None, password=None, timeout=None, get_info='SCHEMA'):
        """
        Binds the class to an ldap server with specified credentials.
        :param host: LDAP server address.
        :param dn: Full DN of the user to log in with.
        :param password: Login user password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :param get_info: String indicating how to pull schema on connection.
        :return: True | False
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling bind_server().')
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

        # Handle for debug mode.
        if self.debug:
            logger.info('host: {0}'.format(host))
            logger.info('dn: {0}'.format(dn))
            logger.info('timeout: {0}'.format(timeout))
            logger.info('get_info: {0}'.format(get_info))

        # Attempt server bind.
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
            if self._ldap_connection is not None and self._ldap_connection.bound:
                self._ldap_connection.unbind()
                logger.debug('Unbound connection: {0}'.format(self._ldap_connection))
        except AttributeError as err:
            logger.info('Failed to unbind server: {0}'.format(err))

    def search(self, search_base=None, search_filter=None, attributes=None, timeout=None, search_scope='LEVEL',
               paged_size=1):
        """
        Searches for the users in the ldap server based on a filter and return specified attributes.
        Assumes ldap connection is already made.

        Note: To view all user attributes, pass the "attributes" as a string of "ALL_ATTRIBUTES".

        :param search_base: The base DN to search.
        :param search_filter: The LDAP filter to use when searching.
        :param attributes: A list of attributes to return | "ALL_ATTRIBUTES".
        :param timeout: Number of seconds to wait before timing out the search.
        :param search_scope: The scope in which to search in.
        :param paged_size: Number of records to return.
        :return: None - Nothing found | Response - The response from the ldap server
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling search().')
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

        # Handle for debug mode.
        if self.debug:
            logger.info('search_base: {0}'.format(search_base))
            logger.info('search_filter: {0}'.format(search_filter))
            logger.info('attributes: {0}'.format(attributes))
            logger.info('timeout: {0}'.format(timeout))
            logger.info('search_scope: {0}'.format(search_scope))
            logger.info('paged_size: {0}'.format(paged_size))

        # Attempt search.
        try:
            self._ldap_connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                paged_size=paged_size,
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

        # collect response
        if paged_size == 1:
            return self._ldap_connection.response[0]['attributes']
        else:
            response_attributes = []
            for response_attribute in self._ldap_connection.response:
                response_attributes.append(response_attribute['attributes'])
            return response_attributes

    def authenticate_with_known_uid(self, host=None, dn=None, password=None, timeout=None, get_info='SCHEMA'):
        """
        Attempts LDAP authentication with a known, valid and existing UID.
        Accomplishes this by binding to prove user exists and credentials are valid, then immediately unbinds.
        :param host: Ldap server address.
        :param dn: Full DN of the user to log in with.
        :param password: User's password.
        :param timeout: Number of seconds to wait before timing out the connection.
        :param get_info: String indicating how to pull schema on connection.
        :return: Array - [Boolean - Authentication success, String - status_message]
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling authenticate_With_known_id().')
        logger.debug('Attempting user authentication with known UID.')

        # Define kwarg values.
        if host is None:
            host = self.config['host']
        if dn is None:
            dn = self.config['master_dn']
        if password is None:
            password = self.config['master_password']
        if timeout is None:
            timeout = int(self.config['connection_timeout'])

        # Handle for debug mode.
        if self.debug:
            logger.info('host: {0}'.format(host))
            logger.info('dn: {0}'.format(dn))
            logger.info('timeout: {0}'.format(timeout))
            logger.info('get_info: {0}'.format(get_info))

        # Attempt authentication.
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

    def authenticate_with_unknown_uid(self, uid, pw, host=None, dn=None, password=None, search_base=None,
                                      search_filter=None, conn_timeout=None, search_timeout=None, get_info='SCHEMA'):
        """
        Attempts LDAP authentication with a UID that may or may not be valid. Ex: Such as input from a user.

        First logs into server with known user. Then attempts to find user with given uid.
        On success, reads user values, disconnects and attempts the authenticate_with_known_uid function.
        :param uid: User UID to search for.
        :param pw: User password to attempt login with.
        :param host: Ldap server address.
        :param dn: Full DN of the a known user.
        :param password: Known user's password.
        :param search_base: The base user DN to search.
        :param search_filter: The LDAP filter to use when searching.
        :param conn_timeout: Number of seconds to wait before timing out the connection.
        :param search_timeout: Number of seconds to wait before timing out the search.
        :param get_info: String indicating how to pull schema on connection.
        :return: Array - [Boolean - Authentication success, String - status_message]
        """
        # Handle for debug mode.
        if self.debug:
            logger.info('Calling authenticate_with_unknown_id().')
        logger.debug('Attempting user authentication with unknown UID.')

        required_arg_failure = False

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
                required_arg_failure = True
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
        default_uid = self.config['default_uid']

        # Handle for debug mode.
        if self.debug:
            logger.info('uid: {0}'.format(uid))
            logger.info('host: {0}'.format(host))
            logger.info('dn: {0}'.format(dn))
            logger.info('search_base: {0}'.format(search_base))
            logger.info('search_filter: {0}'.format(search_filter))
            logger.info('conn_timeout: {0}'.format(conn_timeout))
            logger.info('search_timeout: {0}'.format(search_timeout))
            logger.info('get_info: {0}'.format(get_info))

        # Check if any required arg checks failed. If so, cancel search by exiting.
        if required_arg_failure:
            return None

        # Bind to server with known account.
        connection = self.bind_server(host, dn, password, conn_timeout, get_info=get_info)
        if connection:
            # Search for user with given UID.
            search_filter = search_filter.format(uid)
            results = self.search(search_base, search_filter, attributes=[default_uid], timeout=search_timeout)
            self.unbind_server()

            if results is not None:
                # UID found. Disconnect from known account and attempt login with found account.
                user_dn = '{0}{1}'.format('{0}={1},'.format(default_uid, results[default_uid][0]), search_base)
                results = self.authenticate_with_known_uid(host, user_dn, pw, get_info=get_info)
                return results
            else:
                # Failed to find user with given uid.
                return [False, 'Failed to find user with given UID.']
        else:
            # Failed to connect to server.
            return [False, 'Failed to connect to ldap server.']
