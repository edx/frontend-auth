## 

* [redirectToLogin(redirectUrl)](#redirectToLogin)
* [redirectToLogout(redirectUrl)](#redirectToLogout)
* [getAuthenticatedApiClient(config)](#getAuthenticatedApiClient) ⇒ [<code>HttpClient</code>](#HttpClient)
* [getAuthenticatedUserAccessToken()](#getAuthenticatedUserAccessToken) ⇒ [<code>Promise.&lt;UserAccessToken&gt;</code>](#UserAccessToken)
* [ensureAuthenticatedUser(route)](#ensureAuthenticatedUser) ⇒ [<code>Promise.&lt;UserAccessToken&gt;</code>](#UserAccessToken)

## 

* [HttpClient](#HttpClient)
* [UserAccessToken](#UserAccessToken)

<a name="redirectToLogin"></a>

## redirectToLogin(redirectUrl)
Redirect the user to login

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| redirectUrl | <code>string</code> | the url to redirect to after login |

<a name="redirectToLogout"></a>

## redirectToLogout(redirectUrl)
Redirect the user to logout

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| redirectUrl | <code>string</code> | the url to redirect to after logout |

<a name="getAuthenticatedApiClient"></a>

## getAuthenticatedApiClient(config) ⇒ [<code>HttpClient</code>](#HttpClient)
Gets the apiClient singleton which is an axios instance.

**Kind**: global function  
**Returns**: [<code>HttpClient</code>](#HttpClient) - Singleton. A configured axios http client  

| Param | Type | Description |
| --- | --- | --- |
| config | <code>object</code> |  |
| [config.appBaseUrl] | <code>string</code> |  |
| [config.authBaseUrl] | <code>string</code> |  |
| [config.loginUrl] | <code>string</code> |  |
| [config.logoutUrl] | <code>string</code> |  |
| [config.handleEmptyAccessToken] | <code>function</code> | (optional) |
| [config.loggingService] | <code>object</code> | requires logError and logInfo methods |
| [config.refreshAccessTokenEndpoint] | <code>string</code> |  |
| [config.accessTokenCookieName] | <code>string</code> |  |
| [config.csrfTokenApiPath] | <code>string</code> |  |

<a name="getAuthenticatedUserAccessToken"></a>

## getAuthenticatedUserAccessToken() ⇒ [<code>Promise.&lt;UserAccessToken&gt;</code>](#UserAccessToken)
Gets the authenticated user's access token. Null is

**Kind**: global function  
**Returns**: [<code>Promise.&lt;UserAccessToken&gt;</code>](#UserAccessToken) - Resolves to null if the user is unauthenticated  
<a name="ensureAuthenticatedUser"></a>

## ensureAuthenticatedUser(route) ⇒ [<code>Promise.&lt;UserAccessToken&gt;</code>](#UserAccessToken)
Ensures a user is authenticated. It will redirect to login when not authenticated.

**Kind**: global function  

| Param | Type | Description |
| --- | --- | --- |
| route | <code>string</code> | to return user after login when not authenticated. |

<a name="HttpClient"></a>

## HttpClient
A configured axios client. See axios docs for more
info https://github.com/axios/axios. All the functions
below accept isPublic and isCsrfExempt in the request
config options. Setting these to true will prevent this
client from attempting to refresh the jwt access token
or a csrf token respectively.

```
 // A public endpoint (no jwt token refresh)
 apiClient.get('/path/to/endpoint', { isPublic: true });
```

```
 // A csrf exempt endpoint
 apiClient.post('/path/to/endpoint', { data }, { isCsrfExempt: true });
```

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| get | <code>function</code> |  |
| head | <code>function</code> |  |
| options | <code>function</code> |  |
| delete | <code>function</code> | (csrf protected) |
| post | <code>function</code> | (csrf protected) |
| put | <code>function</code> | (csrf protected) |
| patch | <code>function</code> | (csrf protected) |

<a name="UserAccessToken"></a>

## UserAccessToken
**Kind**: global typedef  
**Properties**

| Name | Type |
| --- | --- |
| userId | <code>string</code> | 
| username | <code>string</code> | 
| roles | <code>array</code> | 
| administrator | <code>bool</code> | 

