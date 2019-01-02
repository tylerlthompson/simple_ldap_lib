
import ldap3
import sys


class SimpleLdapLib(object):

    def __init__(self):
        self._ldap_connection = None

    def __del__(self):
        try:
            if self._ldap_connection.bound:
                self._ldap_connection.unbind()
        except AttributeError:
            pass

    def bind_server(self, host, dn, password, timeout=30):
        """
        Bind the class to an ldap server with specified credentials.
        :param host: LDAP server address
        :param dn: LDAP server login user DN
        :param password: Login user password
        :param timeout: Number of seconds to wait before timing out the connection
        :return: True | False
        """
        try:
            server = ldap3.Server(host=host,
                                  connect_timeout=timeout)
            self._ldap_connection = ldap3.Connection(server=server,
                                                     authentication=ldap3.SIMPLE,
                                                     user=dn,
                                                     password=password,
                                                     raise_exceptions=True)
            self._ldap_connection.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            print("Failed to connect to ldap server.")
            return False
        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
            print("Connection to ldap server timed out.")
            return False
        except:
            print(str(sys.exc_info()))
            return False
        return True

    def search(self, dn, search_filter, attributes, timeout=300):
        """
        Search for the users in the ldap server based on a filter and return specified attributes.
        Assumes ldap connection is already made.
        :param dn: The base DN to search
        :param search_filter: The LDAP filter to use when searching
        :param attributes: A list of attributes to return
        :param timeout: Number of seconds to wait before timing out the connection
        :return: None - Nothing found | Response - The response for then ldap server
        """
        try:
            self._ldap_connection.search(search_base=dn,
                                         search_filter=search_filter,
                                         search_scope=ldap3.LEVEL,
                                         paged_size=1,
                                         attributes=attributes,
                                         time_limit=timeout)
        except ldap3.core.exceptions.LDAPAdminLimitExceededResult:
            print(self._ldap_connection.response)
        except:
            print(sys.exc_info())
            return None

        # user not found
        if not self._ldap_connection.response:
            print("No users found.")
            return None

        # print(self._ldap_connection.response[0])

        return self._ldap_connection.response

    # def authenticate(self, dn, password, timeout=30):
