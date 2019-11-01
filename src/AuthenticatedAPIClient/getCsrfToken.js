import axios from 'axios';
import { getUrlParts, processAxiosErrorAndThrow } from './utils';

const httpClient = axios.create();
const csrfTokenCache = {};
const csrfTokenRequestPromises = {};

const getCsrfToken = async (url, csrfTokenApiPath) => {
  let urlParts;
  try {
    urlParts = getUrlParts(url);
  } catch (e) {
    // If the url is not parsable it's likely because a relative
    // path was supplied as the url. This is acceptable and in
    // this case we should use the current origin of the page.
    urlParts = getUrlParts(global.location.origin);
  }

  const { protocol, domain } = urlParts;
  const csrfToken = csrfTokenCache[domain];

  if (csrfToken) {
    return csrfToken;
  }

  if (!csrfTokenRequestPromises[domain]) {
    csrfTokenRequestPromises[domain] = httpClient
      .get(`${protocol}://${domain}${csrfTokenApiPath}`)
      .then((response) => {
        csrfTokenCache[domain] = response.data.csrfToken;
        return csrfTokenCache[domain];
      })
      .catch(processAxiosErrorAndThrow)
      .finally(() => {
        delete csrfTokenRequestPromises[domain];
      });
  }

  return csrfTokenRequestPromises[domain];
};

export default getCsrfToken;
