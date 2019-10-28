import Cookies from 'universal-cookie';
import jwtDecode from 'jwt-decode';
import axios from 'axios';
import { logInfo, logError } from '@edx/frontend-logging';

const httpClient = axios.create();
const cookies = new Cookies();

const decodeJwtCookie = (cookieName) => {
  const cookieValue = cookies.get(cookieName);

  if (cookieValue) {
    try {
      return jwtDecode(cookieValue);
    } catch (error) {
      logInfo('Error decoding JWT token.', { error, cookieValue });
    }
  }

  return null;
};

const isTokenExpired = token => !token || token.exp < Date.now() / 1000;

export default class AccessToken {
  constructor({ cookieName, refreshEndpoint }) {
    this.cookieName = cookieName;
    this.refreshEndpoint = refreshEndpoint;
  }

  refresh() {
    if (this.refreshRequestPromise === undefined) {
      this.refreshRequestPromise = new Promise((resolve, reject) => {
        httpClient.post(this.refreshEndpoint)
          .then((axiosResponse) => {
            const decodedAccessToken = decodeJwtCookie(this.cookieName);

            if (!decodedAccessToken) {
              const error = new Error('Access token is still null after successful refresh.');
              error.isIrrecoverable = true;
              // This is an unexpected case. The refresh endpoint should
              // set the cookie that is needed. See ARCH-948 for more
              // information on a similar situation that was happening
              // prior to this refactor in Oct 2019.
              logError(`frontend-auth: ${error.message}`, { axiosResponse });
              reject(error);
            }

            resolve(decodedAccessToken);
          })
          .catch(() => {
            // In this case, we learn that the user is not authenticated.
            // TODO: Network timeouts and other problems will end up in
            // this block of code. We could add logic for retrying token
            // refreshes if we wanted to.

            // Clean up the cookie if it exists to eliminate any situation
            // where the cookie is not expired but the jwt is expired.
            cookies.remove(this.cookieName);

            const decodedAccessToken = null;
            resolve(decodedAccessToken);
          })
          .finally(() => {
            delete this.refreshRequestPromise;
          });
      });
    }

    return this.refreshRequestPromise;
  }

  async get() {
    let decodedAccessToken = decodeJwtCookie(this.cookieName);

    if (isTokenExpired(decodedAccessToken)) {
      decodedAccessToken = await this.refresh();
    }

    if (!decodedAccessToken) {
      return null;
    }

    const authenticatedUserAndAccessToken = {
      authenticatedUser: {
        userId: decodedAccessToken.user_id,
        username: decodedAccessToken.preferred_username,
        roles: decodedAccessToken.roles ? decodedAccessToken.roles : [],
        administrator: decodedAccessToken.administrator,
      },
      decodedAccessToken,
    };

    return authenticatedUserAndAccessToken;
  }
}
