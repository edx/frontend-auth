
import { logError, logInfo } from '@edx/frontend-logging';
import Cookies from 'universal-cookie';
import axios from 'axios';
import AccessToken from '../AccessToken';

jest.mock('axios', () => {
  const singleton = {
    get: jest.fn().mockReturnValue(Promise.resolve('success')),
    post: jest.fn().mockReturnValue(Promise.resolve('success')),
  };

  return {
    create: () => singleton,
  };
});

// Set up mocks
const mockCookies = new Cookies();
const mockAxios = axios.create();

// Helper to reset all the mocks used in the test
const resetMocks = () => {
  logError.mockReset();
  logInfo.mockReset();
  mockCookies.get.mockReset();
  mockAxios.post.mockReset();
  mockAxios.get.mockReset();
};


// Create JWT Tokens

const yesterday = new Date();
yesterday.setDate(yesterday.getDate() - 1);
const tomorrow = new Date();
tomorrow.setDate(tomorrow.getDate() + 1);

const jwt = { user_id: '12345' };
const expiredJwt = Object.assign({ exp: yesterday.getTime() / 1000 }, jwt);
const encodedExpiredJwt = `header.${btoa(JSON.stringify(expiredJwt))}`;
const validJwt = Object.assign({ exp: tomorrow.getTime() / 1000 }, jwt);
const encodedValidJwt = `header.${btoa(JSON.stringify(validJwt))}`;


describe('AccessToken', () => {
  const defaultParameters = {
    cookieName: 'test',
    refreshEndpoint: '/v1/refresh',
    handleUnexpectedRefreshFailure: jest.fn(),
  };


  describe('Instantiation', () => {
    beforeEach(() => {
      resetMocks();
    });

    it('Uses a valid jwt cookie token if it exists on instantiation', () => {
      mockCookies.get.mockReturnValue(encodedValidJwt);
      // eslint-disable-next-line no-unused-vars
      const accessToken = new AccessToken(defaultParameters);
      expect(mockAxios.post).not.toHaveBeenCalled();
    });

    it('Refreshes if existing jwt cookie token is expired on instantiation', () => {
      mockCookies.get.mockReturnValue(encodedExpiredJwt);
      mockAxios.post.mockImplementationOnce(() => {
        mockCookies.get.mockReturnValue(encodedValidJwt);
        return Promise.resolve();
      });

      const accessToken = new AccessToken(defaultParameters);

      expect(mockAxios.post).toHaveBeenCalled();
      expect(accessToken.refreshPromise).not.toBeUndefined();
      return accessToken.refreshPromise.finally(() => {
        expect(accessToken.value).toEqual(validJwt);
      });
    });

    it('Refreshes if no jwt cookie token exists on instantiation', () => {
      mockCookies.get.mockReturnValue(undefined);
      mockAxios.post.mockImplementationOnce(() => {
        mockCookies.get.mockReturnValue(encodedValidJwt);
        return Promise.resolve();
      });

      const accessToken = new AccessToken(defaultParameters);

      expect(mockAxios.post).toHaveBeenCalled();
      expect(accessToken.refreshPromise).not.toBeUndefined();
      return accessToken.refreshPromise.finally(() => {
        expect(accessToken.value).toEqual(validJwt);
      });
    });
  });

  describe('accessToken.request()', () => {
    mockCookies.get.mockReturnValue(encodedValidJwt);
    mockAxios.post.mockImplementation(() => Promise.resolve());

    const accessToken = new AccessToken(defaultParameters);

    beforeEach(() => {
      resetMocks();
      mockCookies.get.mockReturnValue(encodedValidJwt);
      mockAxios.post.mockImplementation(() => Promise.resolve());
      defaultParameters.handleUnexpectedRefreshFailure.mockReset();
    });

    it('makes a refresh request even the if the jwt cookie token is not expired', () => {
      expect(accessToken.isExpired).toBe(false);
      return accessToken.refresh()
        .then(() => {
          expect(mockAxios.post).toHaveBeenCalled();
        });
    });

    it('makes a single request even if called multiple times in succession', () => {
      let resolveRefreshPromisePost;
      mockAxios.post.mockReturnValue(new Promise((resolve) => {
        resolveRefreshPromisePost = resolve;
      }));

      expect(accessToken.isExpired).toBe(false);

      const allRefreshes = Promise.all([
        accessToken.refresh(),
        accessToken.refresh(),
        accessToken.refresh(),
      ]);

      resolveRefreshPromisePost();

      return allRefreshes.then(() => {
        expect(mockAxios.post).toHaveBeenCalledTimes(1);
      });
    });

    it('handles a successful post with an unexpected token refresh failure', () => {
      mockCookies.get.mockReturnValue(undefined);
      mockAxios.post.mockReturnValue(Promise.resolve('responseValue'));

      return accessToken.refresh()
        .catch(() => {
          expect(logError).toHaveBeenCalledWith('frontend-auth: Access token is null after supposedly successful refresh.', {
            axiosResponse: 'responseValue',
          });
          expect(defaultParameters.handleUnexpectedRefreshFailure).toHaveBeenCalled();
        });
    });
  });

  describe('accessToken.readJwtToken()', () => {
    const accessToken = new AccessToken(defaultParameters);

    beforeEach(() => {
      resetMocks();
      mockAxios.post.mockImplementation(() => Promise.resolve());
    });

    it('handles a failure to read the cookie', () => {
      mockCookies.get.mockImplementation(() => {
        throw new Error('Could not read cookie');
      });

      accessToken.readJwtToken();

      expect(logInfo).toHaveBeenCalledWith(`Error reading the access token cookie: ${defaultParameters.cookieName}.`);
      expect(accessToken.value).toBeNull();
      expect(accessToken.isExpired).toBe(true);
    });

    it('handles a failure to decode the jwt', () => {
      mockCookies.get.mockReturnValue('a malformed jwt string');

      accessToken.readJwtToken();

      expect(logInfo).toHaveBeenCalledWith('Error decoding JWT token.', expect.objectContaining({
        jwtDecodeError: expect.any(Error),
        cookieValue: 'a malformed jwt string',
      }));
      expect(accessToken.value).toBeNull();
      expect(accessToken.isExpired).toBe(true);
    });
  });
});
