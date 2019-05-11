
# Python - Simple LDAP Library

## Description
A project to extend functionality of Python's ldap3 module.

For information about LDAP values specific to WMU, see the wiki.

## Git Submodules
This project should be used as a "git submodule". Git submodules are essentially projects that are meant to be used
within other projects.

### Installing Submodules
Submodules can be imported into another project with the command
* ``git submodule add https://git.ceas.wmich.edu/Python/SimpleLdapLib.git``

### Initializing Submodules
When you clone a repo that uses submodles, you'll need to initialize the submodules before they can be accessed. This
can be done in one of two ways:
* Add the `--recursive` tag when you clone the project. This will also get all submodules (assuming they're defined
within the master branch)
    * Ex: ``git clone --recursive <project url>``
* If the original project was already cloned, or if the submodule wasn't in the master branch, use
    * ``git submodule update --init --recursive``

### Updating Submodules
Any projects that use a submodule will automatically track which commit is being used. Thus, when a submodule is
updated, the projects using them will have to update which commit they point to. This is accomplished with
    * ``git submodule foreach git pull origin master`` (make sure you commit the change, as well)

## Usage

### Passing and Setting LDAP Info
This project needs to know the settings of the LDAP entity it connects to. This can be provided one of several ways:

* By config:
    * The values can be provided in `resources/config.py`. All methods will automatically use these values, but if
    desired, they can also be overridden through individual functions.
* As function args:
    * Every function has args to set the necessary LDAP settings. If going this route, then they will need to be passed
    every single time any function is called.
* Through the `set_*` functions:
    * The `set_host`, `set_master_account`, and `set_search_base` functions will take in the appropriate values, and
    then retain them as if they were provided in the config. If desired, they can still be overridden through individual
    functions.
    * Generally, these probably should be called when the simple_ldap class is first initialized.

### SimpleLdap Functions

* `authenticate` - For when you have a known valid username and want to attempt to authenticate with a provided password.
* `authenticate_with_uid` - For when you have a username that may or may not be valid (such as user input), but you
    want to attempt authentication with a provided password.
* `search` - For when you want to acquire specific user attributes from the LDAP server.
    * If authentication is required (which should be more often than not), then use one of the above two methods first.
    Only proceed to search.
    * Normally, the search attributes should be an array of all the values you want to return. However, on the occasion
    you wish to get all attributes, pass a string of `ALL_ATTRIBUTES` Instead of an array.

## Arg Explanations for those unfamiliar with LDAP
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
