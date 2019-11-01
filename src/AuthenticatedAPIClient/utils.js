import { getLoggingService } from './index';

// Lifted from here: https://regexr.com/3ok5o
const urlRegex = /([a-z]{1,2}tps?):\/\/((?:(?!(?:\/|#|\?|&)).)+)(?:(\/(?:(?:(?:(?!(?:#|\?|&)).)+\/))?))?(?:((?:(?!(?:\.|$|\?|#)).)+))?(?:(\.(?:(?!(?:\?|$|#)).)+))?(?:(\?(?:(?!(?:$|#)).)+))?(?:(#.+))?/;
const getUrlParts = (url) => {
  const found = url.match(urlRegex);
  try {
    const [
      fullUrl,
      protocol,
      domain,
      path,
      endFilename,
      endFileExtension,
      query,
      hash,
    ] = found;

    return {
      fullUrl,
      protocol,
      domain,
      path,
      endFilename,
      endFileExtension,
      query,
      hash,
    };
  } catch (e) {
    throw new Error(`Could not find url parts from ${url}.`);
  }
};

const logFrontendAuthError = (error) => {
  const prefixedMessageError = Object.create(error);
  prefixedMessageError.message = `[frontend-auth] ${error.message}`;
  getLoggingService().logError(prefixedMessageError, prefixedMessageError.customAttributes);
};

const processAxiosError = (axiosErrorObject) => {
  const error = Object.create(axiosErrorObject);
  const { request, response, config } = error;
  const { url, method } = config;
  /* istanbul ignore else: difficult to enter the request-only error case in a unit test */
  if (response) {
    const { status: requestStatus, data } = response;
    const stringifiedData = JSON.stringify(data) || '';
    const responseIsHTML = stringifiedData.includes('<!DOCTYPE html>');
    // Don't include data if it is just an HTML document, like a 500 error page.
    /* istanbul ignore next */
    const responseData = responseIsHTML ? '<Response is HTML>' : stringifiedData;
    error.customAttributes = {
      ...error.customAttributes,
      errorType: 'api-response-error',
      status: requestStatus,
      responseData,
      url,
      method,
    };
    error.message = `HTTP Client Error: ${requestStatus} ${url} ${data}`;
  } else if (request) {
    error.customAttributes = {
      ...error.customAttributes,
      errorType: 'api-request-error',
      errorData: error.message,
      url,
      method,
    };
    error.message = `HTTP Client Error: ${error.message} ${method} ${url}`;
  } else {
    error.customAttributes = {
      ...error.customAttributes,
      errorType: 'api-request-config-error',
      errorData: error.message,
      url,
      method,
    };
    error.message = `HTTP Client Error: ${error.message} ${method} ${url}`;
  }

  return error;
};

const processAxiosErrorAndThrow = (axiosErrorObject) => {
  throw processAxiosError(axiosErrorObject);
};

export {
  getUrlParts,
  logFrontendAuthError,
  processAxiosError,
  processAxiosErrorAndThrow,
};
