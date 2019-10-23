import PubSub from 'pubsub-js';
import Url from 'url-parse';
import { logInfo } from '@edx/frontend-logging';

const CSRF_TOKEN_REFRESH = 'CSRF_TOKEN_REFRESH';
const CSRF_HEADER_NAME = 'X-CSRFToken';
const CSRF_PROTECTED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];
const csrfTokens = {};
let queueRequests = false;

// Apply default configuration options to the Axios HTTP client.
function applyAxiosDefaults(authenticatedAPIClient) {
  /* eslint-disable no-param-reassign */
  authenticatedAPIClient.defaults.withCredentials = true;
  authenticatedAPIClient.defaults.headers.common['USE-JWT-COOKIE'] = true;
  /* eslint-enable no-param-reassign */
}

// Apply auth-related interceptors to the Axios HTTP Client.
function applyAxiosInterceptors(authenticatedAPIClient) {
  /**
   * Ensure we have a CSRF token header when making POST, PUT, and DELETE requests.
   */
  function ensureCsrfToken(request) {
    const originalRequest = request;
    const method = request.method.toUpperCase();
    const isCsrfExempt = authenticatedAPIClient.isCsrfExempt(originalRequest.url);
    if (!isCsrfExempt && CSRF_PROTECTED_METHODS.includes(method)) {
      const url = new Url(request.url);
      const { protocol } = url;
      const { host } = url;
      const csrfToken = csrfTokens[host];
      if (csrfToken) {
        request.headers[CSRF_HEADER_NAME] = csrfToken;
      } else {
        if (!queueRequests) {
          queueRequests = true;
          authenticatedAPIClient.getCsrfToken(protocol, host)
            .then((response) => {
              queueRequests = false;
              PubSub.publishSync(CSRF_TOKEN_REFRESH, response.data.csrfToken);
            });
        }

        return new Promise((resolve) => {
          logInfo(`Queuing API request ${originalRequest.url} while CSRF token is retrieved`);
          PubSub.subscribeOnce(CSRF_TOKEN_REFRESH, (msg, token) => {
            logInfo(`Resolving queued API request ${originalRequest.url}`);
            csrfTokens[host] = token;
            originalRequest.headers[CSRF_HEADER_NAME] = token;
            resolve(originalRequest);
          });
        });
      }
    }
    return request;
  }

  function ensureValidJWTCookie(axiosRequestConfig) {
    if (!authenticatedAPIClient.accessToken.isExpired) {
      return Promise.resolve(axiosRequestConfig);
    }
    return authenticatedAPIClient.accessToken.refresh().then(() => axiosRequestConfig);
  }

  // Log errors and info for unauthorized API responses
  function handleUnauthorizedAPIResponse(error) {
    const response = error && error.response;
    const errorStatus = response && response.status;
    const requestUrl = response && response.config && response.config.url;
    const requestIsTokenRefresh = requestUrl === authenticatedAPIClient.refreshAccessTokenEndpoint;

    switch (errorStatus) { // eslint-disable-line default-case
      case 401:
        if (requestIsTokenRefresh) {
          logInfo(`Unauthorized token refresh response from ${requestUrl}. This is expected if the user is not yet logged in.`);
        } else {
          logInfo(`Unauthorized API response from ${requestUrl}`);
        }
        break;
      case 403:
        logInfo(`Forbidden API response from ${requestUrl}`);
        break;
    }

    return Promise.reject(error);
  }

  // Apply Axios interceptors
  // Axios runs the interceptors in reverse order from how they are listed.
  // ensureValidJWTCookie needs to run first to ensure the user is authenticated
  // before making the CSRF token request.
  const requestInterceptors = [ensureCsrfToken, ensureValidJWTCookie];
  for (let i = 0; i < requestInterceptors.length; i += 1) {
    authenticatedAPIClient.interceptors.request.use(
      requestInterceptors[i],
      error => Promise.reject(error),
    );
  }
  authenticatedAPIClient.interceptors.response.use(
    response => response,
    handleUnauthorizedAPIResponse,
  );
}

export {
  applyAxiosDefaults,
  applyAxiosInterceptors,
};
