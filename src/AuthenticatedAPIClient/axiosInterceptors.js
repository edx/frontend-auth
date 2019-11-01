
import { getConfig } from './index';
import { processAxiosError } from './utils';
import getCsrfToken from './getCsrfToken';
import getJwtToken from './getJwtToken';

const csrfTokenProviderInterceptor = (options) => {
  const { csrfTokenApiPath, isExempt } = options;

  // Creating the interceptor inside this closure to
  // maintain reference to the options supplied.
  const interceptor = async (axiosRequestConfig) => {
    if (isExempt(axiosRequestConfig)) {
      return axiosRequestConfig;
    }
    const { url } = axiosRequestConfig;
    const csrfToken = await getCsrfToken(url, csrfTokenApiPath);
    const CSRF_HEADER_NAME = 'X-CSRFToken';
    // eslint-disable-next-line no-param-reassign
    axiosRequestConfig.headers[CSRF_HEADER_NAME] = csrfToken;
    return axiosRequestConfig;
  };

  return interceptor;
};

const jwtTokenProviderInterceptor = (options) => {
  const {
    handleEmptyToken,
    tokenCookieName,
    tokenRefreshEndpoint,
    handleUnexpectedRefreshError,
    isExempt,
  } = options;

  // Creating the interceptor inside this closure to
  // maintain reference to the options supplied.
  const interceptor = async (axiosRequestConfig) => {
    if (isExempt(axiosRequestConfig)) {
      return axiosRequestConfig;
    }

    let decodedJwtToken;
    try {
      decodedJwtToken = await getJwtToken(tokenCookieName, tokenRefreshEndpoint);
    } catch (error) {
      handleUnexpectedRefreshError(error);
    }

    if (decodedJwtToken === null && handleEmptyToken !== undefined) {
      handleEmptyToken();
    } else {
      // Add the proper headers to tell the server to look for the jwt cookie
      /* eslint-disable no-param-reassign */
      axiosRequestConfig.withCredentials = true;
      axiosRequestConfig.headers.common['USE-JWT-COOKIE'] = true;
      /* eslint-enable no-param-reassign */
    }

    return axiosRequestConfig;
  };

  return interceptor;
};

const processAxiosRequestErrorInterceptor = (error) => {
  const processedError = processAxiosError(error);
  const { httpErrorStatus } = processedError.customAttributes;
  if (httpErrorStatus === 401 || httpErrorStatus === 403) {
    getConfig('loggingService').logInfo(processedError, processedError.customAttributes);
  }
  return Promise.reject(processedError);
};

export {
  csrfTokenProviderInterceptor,
  jwtTokenProviderInterceptor,
  processAxiosRequestErrorInterceptor,
};
