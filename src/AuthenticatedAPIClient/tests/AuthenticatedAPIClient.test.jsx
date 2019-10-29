/* eslint-disable arrow-body-style */
import axios from 'axios';
import Cookies from 'universal-cookie';
import MockAdapter from 'axios-mock-adapter';
import { NewRelicLoggingService, logInfo, logError } from '@edx/frontend-logging';
import AccessToken from '../AccessToken';
import CsrfTokens from '../CsrfTokens';
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
const mockApiEndpointPath = `${process.env.BASE_URL}/api/v1/test`;

window.location.assign = jest.fn();
const mockCookies = new Cookies();

// This sets the mock adapter on the default instance
const axiosMock = new MockAdapter(axios);
const accessTokenAxios = axios.create();
const accessTokenAxiosMock = new MockAdapter(accessTokenAxios);
AccessToken.__Rewire__('httpClient', accessTokenAxios); // eslint-disable-line no-underscore-dangle
const csrfTokensAxios = axios.create();
const csrfTokensAxiosMock = new MockAdapter(csrfTokensAxios);
CsrfTokens.__Rewire__('httpClient', csrfTokensAxios); // eslint-disable-line no-underscore-dangle


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
  expect(csrfTokensAxiosMock.history.get.length).toBe(1);
};

const expectNoCallToCsrfTokenFetch = () => {
  expect(csrfTokensAxiosMock.history.get.length).toBe(0);
};

const expectRequestToHaveJwtAuth = (request) => {
  expect(request.headers['USE-JWT-COOKIE']).toBe(true);
  expect(request.withCredentials).toBe(true);
};

const expectRequestToHaveCsrfToken = (request) => {
  expect(request.headers['X-CSRFToken']).toEqual(mockCsrfToken);
};

beforeEach(() => {
  axiosMock.reset();
  accessTokenAxiosMock.reset();
  csrfTokensAxiosMock.reset();
  mockCookies.get.mockReset();
  window.location.assign.mockReset();
  logInfo.mockReset();
  logError.mockReset();
  CsrfTokens.__Rewire__('csrfTokenCache', {}); // eslint-disable-line no-underscore-dangle
  axiosMock.onGet('/401').reply(401);
  axiosMock.onGet('/403').reply(403);
  axiosMock.onAny().reply(200);
  csrfTokensAxiosMock
    .onGet(process.env.CSRF_TOKEN_REFRESH)
    .reply(200, { csrfToken: mockCsrfToken });
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
    return client.get(mockApiEndpointPath).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
    });
  });

  it('refreshes the token when an expired one is found', () => {
    setJwtCookieTo(jwtTokens.expired.encoded);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
    return client.get(mockApiEndpointPath).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
    });
  });

  it('does not attempt to refresh the token when a valid one is found', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    return client.get(mockApiEndpointPath).then(() => {
      expectNoCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
    });
  });

  it('refreshes the token only once for multiple outgoing requests', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
    return Promise.all([
      client.get(mockApiEndpointPath),
      client.get(mockApiEndpointPath),
    ]).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
      expectRequestToHaveJwtAuth(axiosMock.history.get[1]);
    });
  });

  // This test case is unexpected, but occurring in production. See ARCH-948 for
  // more information on a similar situation that was happening prior to this
  // refactor in Oct 2019.
  it('throws an error and redirects if the refresh request succeeds but there is no new cookie delivered', () => {
    setJwtCookieTo(null);
    // The JWT cookie is null despite a 200 response.
    setJwtTokenRefreshResponseTo(200, null);
    expect.hasAssertions();
    return client.get(mockApiEndpointPath).catch(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expect(logError).toHaveBeenCalledWith(
        'frontend-auth: Access token is still null after successful refresh.',
        expect.any(Object),
      );
      expectLogout();
    });
  });

  it('throws an error and redirects if the refresh request succeeds but the cookie is malformed', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, 'a malformed jwt');
    expect.hasAssertions();
    return client.get(mockApiEndpointPath).catch(() => {
      // TODO: this error should be truer. Right now the token is not null.
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expect(logError).toHaveBeenCalledWith(
        'frontend-auth: Error decoding JWT token.',
        expect.any(Object),
      );
      expectLogout();
    });
  });

  it('throws an error and redirects if the refresh request fails for an unknown reason', () => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(403, null);
    expect.hasAssertions();
    return client.get(mockApiEndpointPath).catch(() => {
      expectSingleCallToJwtTokenRefresh();
      expectNoCallToCsrfTokenFetch();
      expect(logError).toHaveBeenCalledWith(
        'frontend-auth: Request failed with status code 403',
        expect.any(Object),
      );
      expectLogout();
    });
  });

  it('logs info for 401 unauthorized api responses', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    expect.hasAssertions();
    return client.get('/401').catch(() => {
      expect(logInfo).toHaveBeenCalledWith('Unauthorized API response from /401');
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
    });
  });

  it('logs info for 403 forbidden api responses', () => {
    setJwtCookieTo(jwtTokens.valid.encoded);
    expect.hasAssertions();
    return client.get('/403').catch(() => {
      expect(logInfo).toHaveBeenCalledWith('Forbidden API response from /403');
      expectRequestToHaveJwtAuth(axiosMock.history.get[0]);
    });
  });
});

describe('A POST request when the user is logged in ', () => {
  beforeEach(() => {
    setJwtCookieTo(null);
    setJwtTokenRefreshResponseTo(200, jwtTokens.valid.encoded);
  });

  it('gets a csrf token and adds it to the request', () => {
    return client.post(mockApiEndpointPath).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectRequestToHaveCsrfToken(axiosMock.history.post[0]);
      expectRequestToHaveJwtAuth(axiosMock.history.post[0]);
    });
  });

  it('uses an already fetched csrf token and adds it to the request', () => {
    return client.post(mockApiEndpointPath)
      .then(() => client.post(mockApiEndpointPath))
      .then(() => {
        expectSingleCallToJwtTokenRefresh();
        expectSingleCallToCsrfTokenFetch();
        expectRequestToHaveCsrfToken(axiosMock.history.post[0]);
        expectRequestToHaveJwtAuth(axiosMock.history.post[0]);
        expectRequestToHaveCsrfToken(axiosMock.history.post[1]);
        expectRequestToHaveJwtAuth(axiosMock.history.post[1]);
      });
  });

  it('refreshes the csrf token once for multiple outgoing requests', () => {
    return Promise.all([
      client.post(mockApiEndpointPath),
      client.post(mockApiEndpointPath),
    ]).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectSingleCallToCsrfTokenFetch();
      expectRequestToHaveCsrfToken(axiosMock.history.post[0]);
      expectRequestToHaveJwtAuth(axiosMock.history.post[0]);
      expectRequestToHaveCsrfToken(axiosMock.history.post[1]);
      expectRequestToHaveJwtAuth(axiosMock.history.post[1]);
    });
  });

  it('fetches a csrf token from the host in the BASE_URL if the url is a path', () => {
    return client.post('/path/endpoint')
      .then(() => {
        expectSingleCallToJwtTokenRefresh();
        expectSingleCallToCsrfTokenFetch();
        expectRequestToHaveCsrfToken(axiosMock.history.post[0]);
        expectRequestToHaveJwtAuth(axiosMock.history.post[0]);
        expect(csrfTokensAxiosMock.history.get[0].url)
          .toEqual(`${global.location.origin}${authConfig.csrfTokenApiPath}`);
      });
  });
});

describe('A GET request when the user is logged out', () => {
  beforeEach(() => {
    setJwtTokenRefreshResponseTo(401, null);
  });

  it('redirects to login when no token exists and refreshing fails', () => {
    setJwtCookieTo(null);
    return client.get(mockApiEndpointPath).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectLogin();
    });
  });

  it('redirects to login when an expired token exists and refreshing fails', () => {
    setJwtCookieTo(jwtTokens.expired.encoded);
    return client.get(mockApiEndpointPath).then(() => {
      expectSingleCallToJwtTokenRefresh();
      expectLogin();
    });
  });
});

describe('AuthenticatedAPIClient auth interface', () => {
  it('can go to login with different redirect url parameters', () => {
    client.login('http://edx.org/dashboard');
    expectLogin('http://edx.org/dashboard');
    client.login();
    expectLogin(process.env.BASE_URL);
  });

  it('can go to logout with different redirect url parameters', () => {
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

    // This test case is unexpected, but occurring in production. See ARCH-948 for
    // more information on a similar situation that was happening prior to this
    // refactor in Oct 2019.
    it('throws an error and redirects to logout if there was a problem getting the jwt cookie', () => {
      setJwtCookieTo(null);
      // The JWT cookie is null despite a 200 response.
      setJwtTokenRefreshResponseTo(200, null);
      expect.hasAssertions();
      return client.ensureAuthenticatedUser().catch(() => {
        expectSingleCallToJwtTokenRefresh();
        expectLogout();
        expect(logError).toHaveBeenCalledWith(
          'frontend-auth: Access token is still null after successful refresh.',
          expect.any(Object),
        );
      });
    });
  });

  describe('ensureAuthenticatedUser when the user is logged out', () => {
    beforeEach(() => {
      setJwtTokenRefreshResponseTo(401, null);
    });

    it('attempts to refresh a missing jwt token and redirects user to login', () => {
      setJwtCookieTo(null);
      return client.ensureAuthenticatedUser('/route').then((authenticatedUserAccessToken) => {
        expect(authenticatedUserAccessToken).toBeNull();
        expectSingleCallToJwtTokenRefresh();
        expectLogin(`${process.env.BASE_URL}/route`);
      });
    });

    it('throws an error and does not redirect if the referrer is the login page', () => {
      jest.spyOn(global.document, 'referrer', 'get').mockReturnValue(process.env.LOGIN_URL);
      setJwtCookieTo(null);
      expect.hasAssertions();
      return client.ensureAuthenticatedUser().catch(() => {
        expectSingleCallToJwtTokenRefresh();
        expect(window.location.assign).not.toHaveBeenCalled();
        expect(logError).toHaveBeenCalledWith('frontend-auth: Redirect from login page. Rejecting to avoid infinite redirect loop.');
      });
    });
  });
});
