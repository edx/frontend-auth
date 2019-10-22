import Cookies from 'universal-cookie';
import jwtDecode from 'jwt-decode';


function getAuthenticatedUserFromDecodedAccessToken(decodedAccessToken) {
  /* istanbul ignore next */
  if (decodedAccessToken === null) {
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
  httpClient.accessTokenCookieName = authConfig.accessTokenCookieName;
  httpClient.userInfoCookieName = authConfig.userInfoCookieName;
  httpClient.csrfTokenApiPath = authConfig.csrfTokenApiPath;
  httpClient.loginUrl = authConfig.loginUrl;
  httpClient.logoutUrl = authConfig.logoutUrl;
  httpClient.refreshAccessTokenEndpoint = authConfig.refreshAccessTokenEndpoint;
  httpClient.handleRefreshAccessTokenFailure = authConfig.handleRefreshAccessTokenFailure;
  httpClient.loggingService = authConfig.loggingService;

  /**
   * We will not try to refresh an expired access token before
   * making requests to these auth-related URLs.
   */
  httpClient.authUrls = [httpClient.refreshAccessTokenEndpoint];

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
  httpClient.ensureAuthenticatedUser = route => httpClient
    .refreshAccessTokenOnce()
    .then((response) => {
      const refreshedAccessToken = httpClient.getDecodedAccessToken();

      if (refreshedAccessToken === null) {
        // This should never happen, but it does. See ARCH-948 for past research into why.
        const errorMessage = 'Access token is null after supposedly successful refresh.';
        httpClient.loggingService.logError(`frontend-auth: ${errorMessage}`, {
          axiosResponse: response,
        });
        httpClient.logout(httpClient.appBaseUrl + route);
      }

      return formatAuthenticatedResponse(refreshedAccessToken);
    })
    .catch(() => {
      const isRedirectFromLoginPage = global.document.referrer &&
      global.document.referrer.startsWith(httpClient.loginUrl);
      if (isRedirectFromLoginPage) {
        throw new Error('Redirect from login page. Rejecting to avoid infinite redirect loop.');
      }
      // The user is not authenticated, send them to the login page.
      httpClient.login(httpClient.appBaseUrl + route);
    });

  // JWT expiration is serialized as seconds since the epoch,
  // Date.now returns the number of milliseconds since the epoch.
  httpClient.isAccessTokenExpired = token => !token || token.exp < Date.now() / 1000;

  httpClient.login = (redirectUrl = authConfig.appBaseUrl) => {
    global.location.assign(`${httpClient.loginUrl}?next=${encodeURIComponent(redirectUrl)}`);
  };

  httpClient.logout = (redirectUrl = authConfig.appBaseUrl) => {
    global.location.assign(`${httpClient.logoutUrl}?redirect_url=${encodeURIComponent(redirectUrl)}`);
  };

  httpClient.refreshAccessToken = () => httpClient.post(httpClient.refreshAccessTokenEndpoint);

  httpClient.refreshAccessTokenPromise = null;

  httpClient.refreshAccessTokenOnce = () => {
    if (!httpClient.isAccessTokenExpired(httpClient.getDecodedAccessToken())) {
      // The token is valid. Carry on.
      return Promise.resolve(httpClient.getDecodedAccessToken());
    }

    if (httpClient.refreshAccessTokenPromise === null) {
      // No token refresh request is in-flight. Make the request.
      httpClient.refreshAccessTokenPromise = httpClient
        .refreshAccessToken()
        .catch((error) => {
          // If no callback is supplied frontend-auth will (ultimately) redirect the user to login.
          // The user is redirected to logout to ensure authentication clean-up, which in turn
          // redirects to login.
          if (httpClient.handleRefreshAccessTokenFailure) {
            httpClient.handleRefreshAccessTokenFailure(error);
          } else {
            httpClient.logout();
          }
          throw error;
        })
        .finally(() => {
          httpClient.refreshAccessTokenPromise = null;
        });
    }

    return httpClient.refreshAccessTokenPromise;
  };

  httpClient.isAuthUrl = url => httpClient.authUrls.includes(url);

  httpClient.getDecodedAccessToken = () => {
    const cookies = new Cookies();
    let decodedToken = null;
    try {
      const cookieValue = cookies.get(httpClient.accessTokenCookieName);
      try {
        if (cookieValue) {
          decodedToken = jwtDecode(cookieValue);
        }
      } catch (error) {
        /* istanbul ignore next */
        httpClient.loggingService.logInfo('Error decoding JWT token.', {
          jwtDecodeError: error,
          cookieValue,
        });
      }
    } catch (error) {
      /* istanbul ignore next */
      httpClient.loggingService.logInfo(`Error reading the cookie: ${httpClient.accessTokenCookieName}.`);
    }

    return decodedToken;
  };

  httpClient.getCsrfToken = (apiProtocol, apiHost) =>
    httpClient.get(`${apiProtocol}//${apiHost}${httpClient.csrfTokenApiPath}`);

  httpClient.isCsrfExempt = url => httpClient.csrfExemptUrls.includes(url);
}
