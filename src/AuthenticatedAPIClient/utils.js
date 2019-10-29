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

// eslint-disable-next-line import/prefer-default-export
export { getUrlParts };
