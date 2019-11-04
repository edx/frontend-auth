import axios from 'axios';
import {
  csrfTokenProviderInterceptor,
  jwtTokenProviderInterceptor,
  processAxiosRequestErrorInterceptor,
} from './axiosInterceptors';
import { logFrontendAuthError } from './utils';
import getJwtToken from './getJwtToken';

let authenticatedAPIClient = null;
let config = null;

function configure(incomingConfig) {
  [
    'appBaseUrl',
    'authBaseUrl',
    'loginUrl',
    'logoutUrl',
    // 'handleEmptyAccessToken', // optional
    'loggingService',
    'refreshAccessTokenEndpoint',
    'accessTokenCookieName',
    'csrfTokenApiPath',
  ].forEach((key) => {
    if (incomingConfig[key] === undefined) {
      throw new Error(`Invalid configuration supplied to frontend auth. ${key} is required.`);
    }
  });

  // validate the logging service
  [
    'logInfo',
    'logError',
  ].forEach((key) => {
    if (incomingConfig.loggingService[key] === undefined) {
      throw new Error(`Invalid configuration supplied to frontend auth. loggingService.${key} must be a function.`);
    }
  });

  config = incomingConfig;
}

function getConfig(property) {
  return config[property];
}

/**
 * Redirect the user to login
 *
 * @param {string} redirectUrl the url to redirect to after login
 */
const redirectToLogin = (redirectUrl = config.appBaseUrl) => {
  global.location.assign(`${config.loginUrl}?next=${encodeURIComponent(redirectUrl)}`);
};

/**
 * Redirect the user to logout
 *
 * @param {string} redirectUrl the url to redirect to after logout
 */
const redirectToLogout = (redirectUrl = config.appBaseUrl) => {
  global.location.assign(`${config.logoutUrl}?redirect_url=${encodeURIComponent(redirectUrl)}`);
};

const handleUnexpectedAccessTokenRefreshError = (error) => {
  // There were unexpected errors getting the access token.
  logFrontendAuthError(error);
  redirectToLogout();
  throw error;
};

/**
 * A configured axios client. See axios docs for more
 * info https://github.com/axios/axios. All the functions
 * below accept isPublic and isCsrfExempt in the request
 * config options. Setting these to true will prevent this
 * client from attempting to refresh the jwt access token
 * or a csrf token respectively.
 * 
 * ```
 *  // A public endpoint (no jwt token refresh)
 *  apiClient.get('/path/to/endpoint', { isPublic: true });
 * ```
 * 
 * ```
 *  // A csrf exempt endpoint
 *  apiClient.post('/path/to/endpoint', { data }, { isCsrfExempt: true });
 * ```
 * 
 * @typedef HttpClient
 * @property {function} get
 * @property {function} head
 * @property {function} options
 * @property {function} delete (csrf protected)
 * @property {function} post (csrf protected)
 * @property {function} put (csrf protected)
 * @property {function} patch (csrf protected)
 */

/**
 * Gets the apiClient singleton which is an axios instance.
 * 
 * @param {object} config 
 * @param {string} [config.appBaseUrl]
 * @param {string} [config.authBaseUrl]
 * @param {string} [config.loginUrl]
 * @param {string} [config.logoutUrl]
 * @param {function} [config.handleEmptyAccessToken] (optional)
 * @param {object} [config.loggingService] requires logError and logInfo methods
 * @param {string} [config.refreshAccessTokenEndpoint]
 * @param {string} [config.accessTokenCookieName]
 * @param {string} [config.csrfTokenApiPath]
 * @returns {HttpClient} Singleton. A configured axios http client
 */
function getAuthenticatedApiClient(authConfig) {
  if (authenticatedAPIClient === null) {
    configure(authConfig);
    authenticatedAPIClient = axios.create();

    // Axios interceptors
    const refreshAccessTokenInterceptor = jwtTokenProviderInterceptor({
      tokenCookieName: config.accessTokenCookieName,
      tokenRefreshEndpoint: config.refreshAccessTokenEndpoint,
      handleEmptyToken: config.handleEmptyAccessToken,
      handleUnexpectedRefreshError: handleUnexpectedAccessTokenRefreshError,
      isExempt: axiosRequestConfig => axiosRequestConfig.isPublic,
    });
    const attachCsrfTokenInterceptor = csrfTokenProviderInterceptor({
      csrfTokenApiPath: config.csrfTokenApiPath,
      isExempt: (axiosRequestConfig) => {
        const { method, isCsrfExempt } = axiosRequestConfig;
        const CSRF_PROTECTED_METHODS = ['post', 'put', 'patch', 'delete'];
        return isCsrfExempt || !CSRF_PROTECTED_METHODS.includes(method);
      },
    });

    // Request interceptors: Axios runs the interceptors in reverse
    // order from how they are listed. Since fetching csrf token does
    // not require jwt authentication, it doesn't matter which
    // happens first.
    authenticatedAPIClient.interceptors.request.use(attachCsrfTokenInterceptor);
    authenticatedAPIClient.interceptors.request.use(refreshAccessTokenInterceptor);

    // Response interceptor: moves axios response error data into
    // the error object at error.customAttributes
    authenticatedAPIClient.interceptors.response.use(
      response => response,
      processAxiosRequestErrorInterceptor,
    );
  }

  return authenticatedAPIClient;
}

/**
 * @typedef UserAccessToken
 * @property {string} userId
 * @property {string} username
 * @property {array} roles
 * @property {bool} administrator
 */

/**
 * Gets the authenticated user's access token. Null is
 *
 * @returns {Promise<UserAccessToken>} Resolves to null if the user is unauthenticated
 */
const getAuthenticatedUserAccessToken = async () => {
  let decodedAccessToken;

  try {
    decodedAccessToken = await getJwtToken(config.accessTokenCookieName, config.refreshAccessTokenEndpoint);
  } catch (error) {
    // There were unexpected errors getting the access token.
    handleUnexpectedAccessTokenRefreshError(error);
  }

  if (decodedAccessToken !== null) {
    return {
      userId: decodedAccessToken.user_id,
      username: decodedAccessToken.preferred_username,
      roles: decodedAccessToken.roles || [],
      administrator: decodedAccessToken.administrator,
    };
  }

  return null;
};

/**
 * Ensures a user is authenticated. It will redirect to login when not authenticated.
 *
 * @param {string} route to return user after login when not authenticated.
 * @returns {Promise<UserAccessToken>}
 */
const ensureAuthenticatedUser = async (route) => {
  const authenticatedUserAccessToken = await getAuthenticatedUserAccessToken();

  if (authenticatedUserAccessToken === null) {
    const isRedirectFromLoginPage = global.document.referrer &&
      global.document.referrer.startsWith(config.loginUrl);

    if (isRedirectFromLoginPage) {
      const redirectLoopError = new Error('Redirect from login page. Rejecting to avoid infinite redirect loop.');
      logFrontendAuthError(redirectLoopError);
      throw redirectLoopError;
    }

    // The user is not authenticated, send them to the login page.
    redirectToLogin(config.appBaseUrl + route);
  }

  return authenticatedUserAccessToken;
};

export {
  configure,
  getConfig,
  getAuthenticatedApiClient,
  ensureAuthenticatedUser,
  getAuthenticatedUserAccessToken,
  redirectToLogin,
  redirectToLogout,
};
