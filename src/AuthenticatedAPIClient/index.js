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

const redirectToLogin = (redirectUrl = config.appBaseUrl) => {
  global.location.assign(`${config.loginUrl}?next=${encodeURIComponent(redirectUrl)}`);
};

const redirectToLogout = (redirectUrl = config.appBaseUrl) => {
  global.location.assign(`${config.logoutUrl}?redirect_url=${encodeURIComponent(redirectUrl)}`);
};

const handleUnexpectedAccessTokenRefreshError = (error) => {
  // There were unexpected errors getting the access token.
  logFrontendAuthError(error);
  redirectToLogout();
  throw error;
};

function getAuthenticatedAPIClient(authConfig) {
  if (authenticatedAPIClient === null) {
    configure(authConfig);

    authenticatedAPIClient = axios.create();

    const ensureAccessTokenInterceptor = jwtTokenProviderInterceptor({
      tokenCookieName: config.accessTokenCookieName,
      tokenRefreshEndpoint: config.refreshAccessTokenEndpoint,
      handleEmptyToken: config.handleEmptyAccessToken || redirectToLogin,
      handleUnexpectedRefreshError: handleUnexpectedAccessTokenRefreshError,
    });

    const attachCsrfTokenInterceptor = csrfTokenProviderInterceptor({
      csrfTokenApiPath: config.csrfTokenApiPath,
    });

    // Apply Axios interceptors
    // Axios runs the interceptors in reverse order from how they are listed.
    // ensureValidJWTCookie needs to run first to ensure the user is authenticated
    // before making the CSRF token request.
    authenticatedAPIClient.interceptors.request.use(attachCsrfTokenInterceptor);
    authenticatedAPIClient.interceptors.request.use(ensureAccessTokenInterceptor);

    authenticatedAPIClient.interceptors.response.use(
      response => response,
      processAxiosRequestErrorInterceptor,
    );
  }

  return authenticatedAPIClient;
}

/**
 * Gets the authenticated user's access token.
 *
 * @returns Promise that resolves to { userId, username, roles, administrator } or null
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
      roles: decodedAccessToken.roles ? decodedAccessToken.roles : [],
      administrator: decodedAccessToken.administrator,
    };
  }

  return null;
};

/**
 * Ensures a user is authenticated, including redirecting to login when not authenticated.
 *
 * @param route: used to return user after login when not authenticated.
 * @returns Promise that resolves to { userId, username, roles, administrator }
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
  getAuthenticatedAPIClient,
  ensureAuthenticatedUser,
  getAuthenticatedUserAccessToken,
  redirectToLogin,
  redirectToLogout,
};
