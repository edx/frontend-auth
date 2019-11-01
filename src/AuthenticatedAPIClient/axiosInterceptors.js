
import { getConfig } from './index';
import { processAxiosError } from './utils';
import getCsrfToken from './getCsrfToken';
import getJwtToken from './getJwtToken';

const CSRF_HEADER_NAME = 'X-CSRFToken';
const CSRF_PROTECTED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

const csrfTokenProviderInterceptor = (options) => {
  const { csrfTokenApiPath } = options;

  // Creating the interceptor inside this closure to
  // maintain reference to the options supplied.
  const interceptor = (axiosRequestConfig) => {
    const { url, method } = axiosRequestConfig;
    const isCsrfTokenRequired = CSRF_PROTECTED_METHODS.includes(method.toUpperCase());

    if (isCsrfTokenRequired) {
      return getCsrfToken(url, csrfTokenApiPath).then((csrfToken) => {
        // eslint-disable-next-line no-param-reassign
        axiosRequestConfig.headers[CSRF_HEADER_NAME] = csrfToken;
        return axiosRequestConfig;
      });
    }

    return Promise.resolve(axiosRequestConfig);
  };

  return interceptor;
};

const jwtTokenProviderInterceptor = (options) => {
  const {
    handleEmptyToken, tokenCookieName, tokenRefreshEndpoint, handleUnexpectedRefreshError,
  } = options;

  // Creating the interceptor inside this closure to
  // maintain reference to the options supplied.
  const interceptor = async (axiosRequestConfig) => {
    let decodedJwtToken;
    try {
      decodedJwtToken = await getJwtToken(tokenCookieName, tokenRefreshEndpoint);
    } catch (error) {
      handleUnexpectedRefreshError(error);
    }
    if (decodedJwtToken === null) {
      handleEmptyToken();
    }

    /* eslint-disable no-param-reassign */
    axiosRequestConfig.withCredentials = true;
    axiosRequestConfig.headers.common['USE-JWT-COOKIE'] = true;
    /* eslint-enable no-param-reassign */
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
