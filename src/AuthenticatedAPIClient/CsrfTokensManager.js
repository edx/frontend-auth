import axios from 'axios';

const httpClient = axios.create();

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

const csrfTokens = {};
const csrfTokenRequestPromises = {};

export default class CsrfTokensManager {
  constructor({ csrfTokenApiPath }) {
    this.csrfTokenApiPath = csrfTokenApiPath;
  }

  async getTokenForUrl(url) {
    let urlParts;
    try {
      urlParts = getUrlParts(url);
    } catch (e) {
      urlParts = getUrlParts(global.location.origin);
    }

    const { protocol, domain } = urlParts;
    const csrfToken = csrfTokens[domain];

    if (csrfToken) {
      return csrfToken;
    }

    if (!csrfTokenRequestPromises[domain]) {
      csrfTokenRequestPromises[domain] = httpClient
        .get(`${protocol}://${domain}${this.csrfTokenApiPath}`)
        .then((response) => {
          csrfTokens[domain] = response.data.csrfToken;
          return csrfTokens[domain];
        })
        .finally(() => {
          delete csrfTokenRequestPromises[domain];
        });
    }

    return csrfTokenRequestPromises[domain];
  }
}
