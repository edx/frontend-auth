
import { getConfig } from './index';
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
    handleEmptyToken, tokenCookieName, tokenRefreshEndpoint,
  } = options;

  // Creating the interceptor inside this closure to
  // maintain reference to the options supplied.
  const interceptor = async (axiosRequestConfig) => {
    const decodedJwtToken = await getJwtToken(tokenCookieName, tokenRefreshEndpoint);
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
  const response = error && error.response;
  const errorStatus = response && response.status;
  const requestUrl = response && response.config && response.config.url;

  switch (errorStatus) { // eslint-disable-line default-case
    case 401:
      getConfig('loggingService').logInfo(`Unauthorized API response from ${requestUrl}`);
      break;
    case 403:
      getConfig('loggingService').logInfo(`Forbidden API response from ${requestUrl}`);
      break;
  }

  return Promise.reject(error);
};

export {
  csrfTokenProviderInterceptor,
  jwtTokenProviderInterceptor,
  processAxiosRequestErrorInterceptor,
};
