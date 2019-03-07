const parseCookieValues = (cookieStr, cookieName) => {
  const values = [];
  const pairs = cookieStr.split(/; */);

  pairs.forEach((pair) => {
    const eqIdx = pair.indexOf('=');

    // skip things that don't look like key=value
    if (eqIdx < 0) {
      return;
    }

    const key = pair.substring(0, eqIdx).trim();
    if (key === cookieName) {
      let val = pair.substring(eqIdx + 1, pair.length).trim();
      // quoted values
      if (val[0] === '"') {
        val = val.slice(1, -1);
      }

      values.push(val);
    }
  });

  return values;
};

export default parseCookieValues;
