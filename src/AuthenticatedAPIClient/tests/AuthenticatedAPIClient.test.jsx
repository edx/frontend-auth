/* eslint-disable arrow-body-style */
import axios from 'axios';
import Cookies from 'universal-cookie';
import MockAdapter from 'axios-mock-adapter';
import { NewRelicLoggingService, logInfo } from '@edx/frontend-logging';
import AccessToken from '../AccessToken';
import axiosConfig from '../axiosConfig';
import getAuthenticatedAPIClient from '../index';

const authConfig = {
  appBaseUrl: process.env.BASE_URL,
  accessTokenCookieName: process.env.ACCESS_TOKEN_COOKIE_NAME,
  csrfTokenApiPath: '/get-csrf-token',
  loginUrl: process.env.LOGIN_URL,
  logoutUrl: process.env.LOGOUT_URL,
  refreshAccessTokenEndpoint: process.env.REFRESH_ACCESS_TOKEN_ENDPOINT,
  loggingService: NewRelicLoggingService, // any concrete logging service will do
};

// Set up mocks
// ---------------------------------------------------------------

const secondsInDay = 60 * 60 * 24;
const yesterdayInSeconds = (Date.now() / 1000) - secondsInDay;
const tomorrowInSeconds = (Date.now() / 1000) + secondsInDay;

const jwtTokens = {
  expired: {
    decoded: {
      user_id: '12345',
      preferred_username: 'test',
      administrator: false,
      exp: yesterdayInSeconds,
    },
  },
  valid: {
    decoded: {
      user_id: '12345',
      preferred_username: 'test',
      administrator: false,
      exp: tomorrowInSeconds,
    },
  },
  validWithRoles: {
    decoded: {
      user_id: '12345',
      preferred_username: 'test',
      administrator: true,
      roles: ['role1', 'role2'],
      exp: tomorrowInSeconds,
    },
  },
};

// encode mock JWT tokens
Object.keys(jwtTokens).forEach((jwtTokenName) => {
  const decodedJwt = jwtTokens[jwtTokenName].decoded;
  jwtTokens[jwtTokenName].encoded = `header.${btoa(JSON.stringify(decodedJwt))}`;
});

const mockCsrfToken = 'thetokenvalue';

window.location.assign = jest.fn();
const mockCookies = new Cookies();

// This sets the mock adapter on the default instance
const mock = new MockAdapter(axios);
mock.onGet('/401').reply(401);
mock.onGet('/403').reply(403);
mock.onGet(process.env.CSRF_TOKEN_REFRESH).reply(200, { csrfToken: mockCsrfToken });
mock.onAny().reply(200);

// This sets the mock adapter on the access token instance
const accessTokenAxios = axios.create();
const accessTokenAxiosMock = new MockAdapter(accessTokenAxios);
const createAccessTokenResponse = (status, jwtCookieResponse = null) => {
  const fn = () => {
    mockCookies.get.mockReturnValue(jwtCookieResponse);
    return [status];
  };
  return fn;
};
accessTokenAxiosMock.onPost().reply(createAccessTokenResponse(jwtTokens.valid.encoded));
AccessToken.__Rewire__('httpClient', accessTokenAxios); // eslint-disable-line no-underscore-dangle

const client = getAuthenticatedAPIClient(authConfig);


// Helpers
const setJwtCookieTo = (jwtCookieValue) => {
  mockCookies.get.mockReturnValue(jwtCookieValue);
};

const setJwtTokenRefreshResponseTo = (status, jwtCookieValue) => {
  accessTokenAxiosMock.onPost().reply(() => {
    setJwtCookieTo(jwtCookieValue);
    return [status];
  });
};

function expectLogout(redirectUrl = process.env.BASE_URL) {
  const encodedRedirectUrl = encodeURIComponent(redirectUrl);
  expect(window.location.assign)
    .toHaveBeenCalledWith(`${process.env.LOGOUT_URL}?redirect_url=${encodedRedirectUrl}`);
}

function expectLogin(redirectUrl = process.env.BASE_URL) {
  const encodedRedirectUrl = encodeURIComponent(redirectUrl);
  expect(window.location.assign)
    .toHaveBeenCalledWith(`${process.env.LOGIN_URL}?next=${encodedRedirectUrl}`);
}

const expectSingleCallToJwtTokenRefresh = () => {
  expect(accessTokenAxiosMock.history.post.length).toBe(1);
};

const expectNoCallToJwtTokenRefresh = () => {
  expect(accessTokenAxiosMock.history.post.length).toBe(0);
};

const expectSingleCallToCsrfTokenFetch = () => {
  const csrfRequests = mock.history.get
    .filter(({ url }) => url.includes(authConfig.csrfTokenApiPath));
  expect(csrfRequests.length).toBe(1);
};

const expectNoCallToCsrfTokenFetch = () => {
  const csrfRequests = mock.history.get
    .filter(({ url }) => url.includes(authConfig.csrfTokenApiPath));
  expect(csrfRequests.length).toBe(0);
};

beforeEach(() => {
  mock.reset();
  accessTokenAxiosMock.reset();
  mockCookies.get.mockReset();
  window.location.assign.mockReset();
  logInfo.mockReset();
  axiosConfig.__Rewire__('csrfTokens', {}); // eslint-disable-line no-underscore-dangle
  mock.onGet('/401').reply(401);
  mock.onGet('/403').reply(403);
  mock.onGet(process.env.CSRF_TOKEN_REFRESH).reply(200, { csrfToken: mockCsrfToken });
  mock.onAny().reply(200);
});

describe('getAuthenticatedAPIClient', () => {
  it('returns a singleton', () => {
    const client1 = getAuthenticatedAPIClient(authConfig);
    const client2 = getAuthenticatedAPIClient(authConfig);
    expect(client2).toBe(client1);
  });
});

describe('A GET request when the user is logged in ', () => {
  it('refreshes the token when none is found', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
    return client.get('a/url').then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
    });
  });

  it('refreshes the token when an expired one is found', () => {
    setJwtCookieTo(jwtTokens.expired.encoded);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
    return client.get('a/url').then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
    });
  });

  it('does not attempt to refresh the token when a valid one is found', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    return client.get('a/url').then(() => {
      expectNoCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
    });
  });

  it('refreshes the token only once for multiple outgoing requests', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
    return Promise.all([client.get('a/url'), client.get('a/url')])
      .then(() => {
        expectSingleCallToJwtTokenRefresh();
        expectNoCallToCsrfTokenFetch();
      });
  });

  it('throws an error and redirects if the refresh request succeeds but there is no new cookie delivered', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, null);
    expect.assertions(4);
    return client.get('a/url').catch((error) => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expect(error.message).toEqual('Access token is still null after successful refresh.');
      expectLogout();
    });
  });

  it('throws an error and redirects if the refresh request succeeds but the cookie is malformed', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, 'a malformed jwt');
    expect.assertions(4);
    return client.get('a/url').catch((error) => {
      // TODO: this error should be truer. Right now the token is not null.
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expect(error.message).toEqual('Access token is still null after successful refresh.');
      expectLogout();
    });
  });

  it('logs info for 401 unauthorized api responses', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    expect.assertions(1);
    return client.get('/401').catch(() => {
      expect(logInfo).toHaveBeenCalledWith('Unauthorized API response from /401');
    });
  });

  it('logs info for 403 forbidden api responses', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    expect.assertions(1);
    return client.get('/403').catch(() => {
      expect(logInfo).toHaveBeenCalledWith('Forbidden API response from /403');
    });
  });
});

describe('A POST request when the user is logged in ', () => {
  beforeEach(() => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
  });

  it('gets a csrf token and adds it to the request', () => {
    return client.post('a/url').then(() => {
      expectSingleCallToJwtTokenRefresh();
      expect(mock.history.post[0].headers['X-CSRFToken']).toEqual(mockCsrfToken);
    });
  });

  it('uses an already fetched csrf token and adds it to the request', () => {
    return client.post('a/url')
      .then(() => client.post('a/url'))
      .then(() => {
        expectSingleCallToJwtTokenRefresh();
        expectSingleCallToCsrfTokenFetch();
        expect(mock.history.post[0].headers['X-CSRFToken']).toEqual(mockCsrfToken);
        expect(mock.history.post[1].headers['X-CSRFToken']).toEqual(mockCsrfToken);
      });
  });

  it('refreshes the csrf token once for multiple outgoing requests', () => {
    return Promise.all([
      client.post('a/url'),
      client.post('a/url'),
    ]).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectSingleCallToCsrfTokenFetch();
      expect(mock.history.post[0].headers['X-CSRFToken']).toEqual(mockCsrfToken);
      expect(mock.history.post[1].headers['X-CSRFToken']).toEqual(mockCsrfToken);
    });
  });
});

describe('A GET request when the user is logged out', () => {
  beforeEach(() => {
    setJwtTokenRefreshResponseTo(401, null);
  });

  it('redirects to login when no token exists and refreshing fails', () => {
    setJwtCookieTo(null);
    return client.get('a/url').then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectLogin();
    });
  });

  it('redirects to login when an expired token exists and refreshing fails', () => {
    setJwtCookieTo(jwtTokens.expired.encoded);
    return client.get('a/url').then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectLogin();
    });
  });
});

describe('AuthenticatedAPIClient auth interface', () => {
  it('can redirect to login', () => {
    client.login('http://edx.org/dashboard');
    expectLogin('http://edx.org/dashboard');
    client.login();
    expectLogin(process.env.BASE_URL);
  });

  it('can redirect to logout', () => {
    client.logout('http://edx.org/');
    expectLogout('http://edx.org/');
    client.logout();
    expectLogout(process.env.BASE_URL);
  });

  describe('ensureAuthenticatedUser when the user is logged in', () => {
    it('refreshes a missing jwt token and returns a user access token', () => {
      setJwtCookieTo(null);
      setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
      return client.ensureAuthenticatedUser().then((authenticatedUserAccessToken) => {
        expect(authenticatedUserAccessToken.decodedAccessToken).toEqual(jwtTokens.valid.decoded);
        expectSingleCallToJwtTokenRefresh();
      });
    });

    it('refreshes a missing jwt token and returns a user access token with roles', () => {
      setJwtCookieTo(null);
      setJwtTokenRefreshResponseTo(200, jwtTokens.validWithRoles.encoded);
      return client.ensureAuthenticatedUser().then((authenticatedUserAccessToken) => {
        expect(authenticatedUserAccessToken.decodedAccessToken).toEqual(jwtTokens.validWithRoles.decoded);
        expectSingleCallToJwtTokenRefresh();
      });
    });

    it('throws and error and redirects to logout if there was a problem getting the jwt cookie', () => {
      setJwtCookieTo(null);
      setJwtTokenRefreshResponseTo(200, null);
      expect.assertions(3);
      return client.ensureAuthenticatedUser().catch((error) => {
        expectSingleCallToJwtTokenRefresh();
        expectLogout();
        expect(error.message).toEqual('Access token is still null after successful refresh.');
      });
    });
  });

  describe('ensureAuthenticatedUser when the user is logged out', () => {
    beforeEach(() => {
      setJwtTokenRefreshResponseTo(401, null);
    });

    it('attempts to refresh a missing jwt token and returns null if the user is logged out', () => {
      setJwtCookieTo(null);
      return client.ensureAuthenticatedUser('/route').then((authenticatedUserAccessToken) => {
        expect(authenticatedUserAccessToken).toBeNull();
        expectSingleCallToJwtTokenRefresh();
        expectLogin(`${process.env.BASE_URL}/route`);
      });
    });

    it('throws an error and does not redirect if the referrer is login user is logged out', () => {
      jest.spyOn(global.document, 'referrer', 'get').mockReturnValue(process.env.LOGIN_URL);
      expect.assertions(3);
      setJwtCookieTo(null);
      return client.ensureAuthenticatedUser().catch((error) => {
        expectSingleCallToJwtTokenRefresh();
        expect(window.location.assign).not.toHaveBeenCalled();
        expect(error.message).toEqual('Redirect from login page. Rejecting to avoid infinite redirect loop.');
      });
    });
  });
});
