-  `redirectToLogin(redirectUrl)`__
-  `redirectToLogout(redirectUrl) <#redirectToLogout>`__
-  `getAuthenticatedApiClient(config) <#getAuthenticatedApiClient>`__ ⇒
   `HttpClient <#HttpClient>`__
-  `getAuthenticatedUserAccessToken() <#getAuthenticatedUserAccessToken>`__
   ⇒ `Promise.<UserAccessToken> <#UserAccessToken>`__
-  `ensureAuthenticatedUser(route) <#ensureAuthenticatedUser>`__ ⇒
   `Promise.<UserAccessToken> <#UserAccessToken>`__

.. _section-1:

-  `HttpClient <#HttpClient>`__
-  `UserAccessToken <#UserAccessToken>`__

redirectToLogin(redirectUrl)
----------------------------

Redirect the user to login

**Kind**: global function

=========== ====== ==================================
Param       Type   Description
=========== ====== ==================================
redirectUrl string the url to redirect to after login
=========== ====== ==================================

redirectToLogout(redirectUrl)
-----------------------------

Redirect the user to logout

**Kind**: global function

=========== ====== ===================================
Param       Type   Description
=========== ====== ===================================
redirectUrl string the url to redirect to after logout
=========== ====== ===================================

getAuthenticatedApiClient(config) ⇒ `HttpClient <#HttpClient>`__
----------------------------------------------------------------

Gets the apiClient singleton which is an axios instance.

| **Kind**: global function
| **Returns**: `HttpClient <#HttpClient>`__ - Singleton. A configured
  axios http client

=================================== ======== =====================================
Param                               Type     Description
=================================== ======== =====================================
config                              object  
[config.appBaseUrl]                 string  
[config.authBaseUrl]                string  
[config.loginUrl]                   string  
[config.logoutUrl]                  string  
[config.handleEmptyAccessToken]     function (optional)
[config.loggingService]             object   requires logError and logInfo methods
[config.refreshAccessTokenEndpoint] string  
[config.accessTokenCookieName]      string  
[config.csrfTokenApiPath]           string  
=================================== ======== =====================================

getAuthenticatedUserAccessToken() ⇒ `Promise.<UserAccessToken> <#UserAccessToken>`__
------------------------------------------------------------------------------------

Gets the authenticated user’s access token. Null is

| **Kind**: global function
| **Returns**: `Promise.<UserAccessToken> <#UserAccessToken>`__ -
  Resolves to null if the user is unauthenticated
| 

ensureAuthenticatedUser(route) ⇒ `Promise.<UserAccessToken> <#UserAccessToken>`__
---------------------------------------------------------------------------------

Ensures a user is authenticated. It will redirect to login when not
authenticated.

**Kind**: global function

===== ====== ==================================================
Param Type   Description
===== ====== ==================================================
route string to return user after login when not authenticated.
===== ====== ==================================================

HttpClient
----------

A configured axios client. See axios docs for more info
https://github.com/axios/axios. All the functions below accept isPublic
and isCsrfExempt in the request config options. Setting these to true
will prevent this client from attempting to refresh the jwt access token
or a csrf token respectively.

::

    // A public endpoint (no jwt token refresh)
    apiClient.get('/path/to/endpoint', { isPublic: true });

::

    // A csrf exempt endpoint
    apiClient.post('/path/to/endpoint', { data }, { isCsrfExempt: true });

| **Kind**: global typedef
| **Properties**

======= ======== ================
Name    Type     Description
======= ======== ================
get     function
head    function
options function
delete  function (csrf protected)
post    function (csrf protected)
put     function (csrf protected)
patch   function (csrf protected)
======= ======== ================

UserAccessToken
---------------

| **Kind**: global typedef
| **Properties**

============= ======
Name          Type
============= ======
userId        string
username      string
roles         array
administrator bool
============= ======

