import AccessToken from './AccessToken';

function getAuthenticatedUserFromDecodedAccessToken(decodedAccessToken) {
  /* istanbul ignore next */
  if (!decodedAccessToken) {
    throw new Error('Decoded access token is required to get authenticated user.');
  }

  return {
    userId: decodedAccessToken.user_id,
    username: decodedAccessToken.preferred_username,
    roles: decodedAccessToken.roles ? decodedAccessToken.roles : [],
    administrator: decodedAccessToken.administrator,
  };
}

function formatAuthenticatedResponse(decodedAccessToken) {
  return {
    authenticatedUser: getAuthenticatedUserFromDecodedAccessToken(decodedAccessToken),
    decodedAccessToken,
  };
}

// Apply the auth-related properties and functions to the Axios API client.
export default function applyAuthInterface(httpClient, authConfig) {
  /* eslint-disable no-param-reassign */
  httpClient.appBaseUrl = authConfig.appBaseUrl;
  httpClient.authBaseUrl = authConfig.authBaseUrl;
  httpClient.userInfoCookieName = authConfig.userInfoCookieName;
  httpClient.csrfTokenApiPath = authConfig.csrfTokenApiPath;
  httpClient.loginUrl = authConfig.loginUrl;
  httpClient.logoutUrl = authConfig.logoutUrl;
  httpClient.refreshAccessTokenEndpoint = authConfig.refreshAccessTokenEndpoint;
  httpClient.handleRefreshAccessTokenFailure = authConfig.handleRefreshAccessTokenFailure;
  httpClient.loggingService = authConfig.loggingService;

  httpClient.accessToken = new AccessToken({
    cookieName: authConfig.accessTokenCookieName,
    refreshEndpoint: authConfig.refreshAccessTokenEndpoint,
    handleUnexpectedRefreshFailure: () => { httpClient.logout(); },
  });

  /**
   * We will not try to retrieve a CSRF token before
   * making requests to these CSRF-exempt URLS.
   */
  httpClient.csrfExemptUrls = [httpClient.refreshAccessTokenEndpoint];

  /**
   * Ensures a user is authenticated, including redirecting to login when not authenticated.
   *
   * @param route: used to return user after login when not authenticated.
   * @returns Promise that resolves to { authenticatedUser: {...}, decodedAccessToken: {...}}
   */
  httpClient.ensureAuthenticatedUser = (route) => {
    if (!httpClient.accessToken.isExpired) {
      return Promise.resolve(formatAuthenticatedResponse(httpClient.accessToken.value));
    }

    return httpClient.accessToken.refresh()
      .then(refreshedAccessToken => formatAuthenticatedResponse(refreshedAccessToken))
      .catch(() => {
        const isRedirectFromLoginPage = global.document.referrer &&
          global.document.referrer.startsWith(httpClient.loginUrl);

        if (isRedirectFromLoginPage) {
          throw new Error('Redirect from login page. Rejecting to avoid infinite redirect loop.');
        }
        // The user is not authenticated, send them to the login page.
        httpClient.login(httpClient.appBaseUrl + route);
      });
  };

  httpClient.login = (redirectUrl = authConfig.appBaseUrl) => {
    global.location.assign(`${httpClient.loginUrl}?next=${encodeURIComponent(redirectUrl)}`);
  };

  httpClient.logout = (redirectUrl = authConfig.appBaseUrl) => {
    global.location.assign(`${httpClient.logoutUrl}?redirect_url=${encodeURIComponent(redirectUrl)}`);
  };

  httpClient.getCsrfToken = (apiProtocol, apiHost) =>
    httpClient.get(`${apiProtocol}//${apiHost}${httpClient.csrfTokenApiPath}`);

  httpClient.isCsrfExempt = url => httpClient.csrfExemptUrls.includes(url);
}
