import axios, {
  AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios';
import { getBackendAccessToken } from './getBackendAccessToken';
import { msalInstance } from '../msalInstance';

export const backendApiClient: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_BACKEND_API_BASE_URL,
  timeout: Number(import.meta.env.VITE_AXIOS_TIMEOUT),
  withCredentials: false,
});

backendApiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    return config;
  },
  (error) => Promise.reject(error),
);

backendApiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    // オリジナルのリクエスト情報を取得
    const originalRequest = error.config as
      | (InternalAxiosRequestConfig & { _retry?: boolean })
      | undefined;
    if (!error.response || !originalRequest) return Promise.reject(error);
    if (originalRequest._retry) return Promise.reject(error);

    if (error.response.status === 401) {
      // 401 Unauthorizedの場合は、アクセストークンを再度取得してオリジナルのリクエストを再試行
      originalRequest._retry = true;
      const account =
        msalInstance.getActiveAccount() ?? msalInstance.getAllAccounts()[0];
      if (!account) {
        return Promise.reject(error);
      }
      try {
        const accessToken = await getBackendAccessToken(account);
        originalRequest.headers.set('Authorization', `Bearer ${accessToken}`);
        return backendApiClient(originalRequest);
      } catch (err) {
        return Promise.reject(err);
      }
    }
    return Promise.reject(error);
  },
);
