import Cookies from 'universal-cookie';
import jwtDecode from 'jwt-decode';
import axios from 'axios';
import { logInfo, logError } from '@edx/frontend-logging';

const httpClient = axios.create();
const cookies = new Cookies();


const getCookieValue = (name) => {
  try {
    return cookies.get(name);
  } catch (error) {
    logInfo(`Error reading the access token cookie: ${name}.`);
    return null;
  }
};

const decodeJwtCookie = (cookieValue) => {
  try {
    return jwtDecode(cookieValue);
  } catch (error) {
    logInfo('Error decoding JWT token.', {
      jwtDecodeError: error,
      cookieValue,
    });
    return null;
  }
};

const isTokenExpired = token => !token || token.exp < Date.now() / 1000;


export default class AccessToken {
  constructor({ cookieName, refreshEndpoint, handleUnexpectedRefreshFailure }) {
    this.cookieName = cookieName;
    this.refreshEndpoint = refreshEndpoint;
    this.handleUnexpectedRefreshFailure = handleUnexpectedRefreshFailure;

    this.readJwtToken();

    if (!this.value || this.isExpired) {
      this.refresh();
    }
  }

  readJwtToken() {
    this.cookieValue = getCookieValue(this.cookieName);

    if (this.cookieValue) {
      this.value = decodeJwtCookie(this.cookieValue);
    } else {
      this.value = null;
    }

    this.isExpired = isTokenExpired(this.value);

    return this.value;
  }

  refresh() {
    if (this.refreshPromise === undefined) {
      this.refreshPromise = httpClient.post(this.refreshEndpoint)
        .then((response) => {
          this.readJwtToken();

          if (!this.value) {
            // This is an unexpected case. The refresh endpoint should
            // set the cookie that is needed. See ARCH-948 for more
            // information on a similar situation that was happening
            // prior to this refactor in Oct 2019.
            const errorMessage = 'Access token is null after supposedly successful refresh.';
            logError(`frontend-auth: ${errorMessage}`, {
              axiosResponse: response,
            });
            // Force applications into their catch handlers for this promise.
            this.handleUnexpectedRefreshFailure(response);
          }

          return this.value;
        })
        // TODO: consider adding a .catch() here to do some logging
        // and then pass the rejection along to the app.
        .finally(() => {
          delete this.refreshPromise;
        });
    }

    return this.refreshPromise;
  }
}
