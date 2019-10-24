
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

const jwt = {
  user_id: '12345',
  preferred_username: 'test',
  administrator: false,
};
const expiredJwt = Object.assign({ exp: yesterday.getTime() / 1000 }, jwt);
const encodedExpiredJwt = `header.${btoa(JSON.stringify(expiredJwt))}`;
const validJwt = Object.assign({ exp: tomorrow.getTime() / 1000 }, jwt);
const encodedValidJwt = `header.${btoa(JSON.stringify(validJwt))}`;
const jwtWithRoles = Object.assign({ roles: ['role1', 'role2'] }, jwt);
const validJwtWithRoles = Object.assign({ exp: tomorrow.getTime() / 1000 }, jwtWithRoles);
const encodedValidJwtWithRoles = `header.${btoa(JSON.stringify(validJwtWithRoles))}`;

describe('AccessToken', () => {
  describe('Instantiation', () => {
    beforeEach(() => {
      resetMocks();
    });

    it('Uses a valid jwt cookie token if it exists on instantiation', () => {
      mockCookies.get.mockReturnValue(encodedValidJwt);
      // eslint-disable-next-line no-unused-vars
      const accessToken = new AccessToken({});
      expect(mockAxios.post).not.toHaveBeenCalled();
    });

    it('Refreshes if existing jwt cookie token is expired on instantiation', () => {
      mockCookies.get.mockReturnValue(encodedExpiredJwt);
      mockAxios.post.mockImplementationOnce(() => {
        mockCookies.get.mockReturnValue(encodedValidJwt);
        return Promise.resolve();
      });

      const accessToken = new AccessToken({});

      expect(mockAxios.post).toHaveBeenCalled();
      return expect(accessToken.refreshRequestPromise).resolves.toEqual(validJwt);
    });

    it('Refreshes if no jwt cookie token exists on instantiation', () => {
      mockCookies.get.mockReturnValue(undefined);
      mockAxios.post.mockImplementationOnce(() => {
        mockCookies.get.mockReturnValue(encodedValidJwt);
        return Promise.resolve();
      });

      const accessToken = new AccessToken({});

      return accessToken.refreshRequestPromise.then((result) => {
        expect(mockAxios.post).toHaveBeenCalled();
        expect(result).toEqual(validJwt);
      });
    });
  });

  describe('accessToken.get()', () => {
    mockCookies.get.mockReturnValue(encodedValidJwt);
    mockAxios.post.mockImplementation(() => Promise.resolve());

    const accessToken = new AccessToken({});

    beforeEach(() => {
      resetMocks();
      mockCookies.get.mockReturnValue(encodedValidJwt);
      mockAxios.post.mockImplementation(() => Promise.resolve());
    });

    it('makes a single request even if called multiple times in succession', () => {
      let resolvePost;
      mockCookies.get.mockReturnValue(undefined);
      mockAxios.post.mockImplementation(() => new Promise((resolve) => {
        resolvePost = resolve;
      }));

      const allRefreshes = Promise.all([
        accessToken.get(),
        accessToken.get(),
        accessToken.get(),
      ]);

      mockCookies.get.mockReturnValue(encodedValidJwt);
      resolvePost();

      return allRefreshes.then(() => {
        expect(mockAxios.post).toHaveBeenCalledTimes(1);
      });
    });

    it('handles a successful post with an unexpected token refresh failure', () => {
      mockCookies.get.mockReturnValue(undefined);
      mockAxios.post.mockReturnValue(Promise.resolve('responseValue'));

      return accessToken.get()
        .catch(() => {
          expect(logError).toHaveBeenCalledWith('frontend-auth: Access token is still null after successful refresh.', {
            axiosResponse: 'responseValue',
          });
        });
    });

    it('handles a failure to decode the jwt', () => {
      mockCookies.get.mockReturnValue('a malformed jwt string');

      return accessToken.get().catch(() => {
        expect(logInfo).toHaveBeenCalledWith('Error decoding JWT token.', expect.objectContaining({
          error: expect.any(Error),
          cookieValue: 'a malformed jwt string',
        }));
      });
    });

    it('decodes a valid jwt cookie', () => {
      mockCookies.get.mockReturnValue(encodedValidJwt);

      return accessToken.get()
        .then((result) => {
          expect(result).toEqual(expect.objectContaining({
            authenticatedUser: {
              administrator: validJwt.administrator,
              roles: [],
              userId: validJwt.user_id,
              username: validJwt.preferred_username,
            },
            decodedAccessToken: validJwt,
          }));
        });
    });

    it('decodes a valid jwt cookie with roles', () => {
      mockCookies.get.mockReturnValue(encodedValidJwtWithRoles);

      return accessToken.get()
        .then((result) => {
          expect(result).toEqual(expect.objectContaining({
            authenticatedUser: {
              administrator: validJwtWithRoles.administrator,
              roles: validJwtWithRoles.roles,
              userId: validJwtWithRoles.user_id,
              username: validJwtWithRoles.preferred_username,
            },
            decodedAccessToken: validJwtWithRoles,
          }));
        });
    });
  });
});
