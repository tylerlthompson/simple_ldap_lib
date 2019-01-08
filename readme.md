
# Python - Simple LDAP Library

## Description
A project to extend functionality of Python's ldap3 module.

## Installation
`pip3 install ldap3`

## Usage
By default, all methods will try to read from the config.<br>
If your LDAP setup is relatively simple, populating the config should be enough.

For more complicated setups (such as where there are multiple LDAP servers/search paths/attributes/etc), individual
method args can be set on function call instead of within the config.

### Arg Explanations for those unfamiliar with LDAP
* **Host** - The IP address or domain of server to connect to. Should begin with ``ldaps://``.
* **DN** - For bind and authenticate methods, the "dn" can be thought of as "the full, unique directory path within LDAP
to the login user".
    * Ex: we want to log in with user having a cn of "Bob". The DN might be something like `"cn=Bob,dc=users,dc=myLdap"`.
* **Search Base** - Can be thought of as "the directory path within LDAP to search in".
    * Ex: We want to search for users in the location "myLdap/users" so we'd have a base of ``"dc=users,dc=myLdap"``.
* **Search Filter** - Can be thought of as "the specific value to search for within the Search Base LDAP folder". Note
that this should be a single string value, encased in parenthesis.
    * Ex: We want to find the user with ``"(cn=Bob)"`` in the given Search Base directory.
* **Attributes** - Once we find an LDAP object through a search, attributes are the specific values of the Object to
return. Note that this should be an array of strings.
    * Ex: We want the attributes ``['cn', 'givenName', 'sn']``.

## Outside Documentation
### Ldap3
https://ldap3.readthedocs.io/

### Ldap Basics
https://ldap.com/basic-ldap-concepts/

### Ldap Search Filter Quick Reference
https://www.ibm.com/support/knowledgecenter/en/SSKTMJ_9.0.1/admin/conf_tableofoperatorsusedinldapsearchsearchfilters_t.html

### DNs, RDNs, and Escape Characters
https://ldap.com/ldap-dns-and-rdns/.exceptions.LD
