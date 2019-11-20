import { camelCaseObject, snakeCaseObject } from '../dataUtils';

class UserAccountApiService {
  constructor(apiClient, baseUrl) {
    this.apiClient = apiClient;
    this.apiBaseUrl = `${baseUrl}/api/user/v1/accounts`;
  }

  getUserAccount(username) {
    return new Promise((resolve, reject) => {
      this.apiClient.get(`${this.apiBaseUrl}/${username}`)
        .then((response) => {
          resolve(camelCaseObject(response.data));
        })
        .catch((error) => {
          reject(error);
        });
    });
  }

  saveUserAccount(username, data) {
    return new Promise((resolve, reject) => {
      this.apiClient.patch(
        `${this.apiBaseUrl}/${username}`,
        snakeCaseObject(data, { deep: true }),
        {
          headers: {
            'Content-Type': 'application/merge-patch+json',
          },
        },
      )
        .then((response) => {
          resolve(camelCaseObject(response.data));
        })
        .catch((error) => {
          reject(error);
        });
    });
  }

  saveUserProfilePhoto(username, formData) {
    return this.apiClient.post(
      `${this.apiBaseUrl}/${username}/image`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      },
    );
  }

  deleteUserProfilePhoto(username) {
    return this.apiClient.delete(`${this.apiBaseUrl}/${username}/image`);
  }
}

export default UserAccountApiService;
