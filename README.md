Apache authorization module for SecurePass
==========================================

This is an Apache (2.2 and 2.4) module for authorizing SecurePass users.
SecurePass provides web single sign-on through the CAS protocol.

This module enhances the Apache authorization features by introducing two rules to restrict access 
to the Apache resources:

* the first rule allows only users belonging to specific SecurePass realm(s) to access the Apache resource
* the second rule allows only users belonging to specific SecurePass group(s) to access the Apache resource

More on SecurePass at http://www.secure-pass.net

To install the module, please read file INSTALL.

Credits
===========================================
I wrote this module starting from Alessandro Lorenzi version at 
https://github.com/AlessandroLorenzi/mod_authz_securepass, which provided authorization based on realms

I added authorization based on groups, which implied:
- call a RESTFul API provided by Securepass (https://beta.secure-pass.net/trac/wiki/GroupsApi), 
  to check if a given user belongs to a given group 
- parse the JSON packet returned
- cache locally, for a configurable time, the user-group mappings returned by the API

To parse the JSON packet, I used a nice parser called jsmn, developed by zserge and available at 
bitbucket.org/zserge/jsmn under the MIT license.

Author
===========================================
gplll1818@gmail.com, Jun 2014 - Jan 2015
