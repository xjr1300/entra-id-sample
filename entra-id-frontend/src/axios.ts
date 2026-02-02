import axios, {
  AxiosError,
  type AxiosInstance,
  type InternalAxiosRequestConfig,
} from 'axios';
import {
  InteractionRequiredAuthError,
  type SilentRequest,
} from '@azure/msal-browser';
import { msalInstance } from './msalInstance';
import { graphLoginRequest } from './authConfig';

export const graphApiClient = axios.create({
  // withCredentialsは、クロスサイト（オリジン間）通信のときに「ブラウザがユーザーに紐づく情報（資格情報）を一緒に送るかどうか」を指定するフラグである。
  // 資格情報には、Cookie、認証ヘッダー、TLSクライアント証明書などが含まれる。
  // クロスサイト通信とは、スキーム、ホスト、ポートのいずれかが異なる場合の通信を示す。
  // withCredentialsをtrueに設定すると、クロスサイト通信の際に、ブラウザは次を行う。
  // - Cookieを送信する
  // - Set-Cookieヘッダーを受け入れる
  // - クライアント証明書があれば送信する
  withCredentials: false,
  timeout: Number(import.meta.env.VITE_AXIOS_TIMEOUT),
});

export const attachMsalInterceptors = (
  client: AxiosInstance,
  loginRequest: SilentRequest,
) => {
  // リクエストインターセプター
  client.interceptors.request.use(
    async (config: InternalAxiosRequestConfig) => {
      const accounts = msalInstance.getAllAccounts();
      if (accounts.length === 0) {
        return config;
      }

      const account = msalInstance.getActiveAccount() || accounts[0];
      msalInstance.setActiveAccount(account);

      const tokenResponse = await msalInstance.acquireTokenSilent({
        ...loginRequest,
        account,
      });

      config.headers.set(
        'Authorization',
        `Bearer ${tokenResponse.accessToken}`,
      );
      return config;
    },
    (error) => Promise.reject(error),
  );

  // レスポンスインターセプター
  client.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config;
      if (!error.response || !originalRequest) {
        return Promise.reject(error);
      }

      if (error.response.status === 401 && !originalRequest._retry) {
        // 401 Unauthorizedの場合は、アクセストークンを再度取得してオリジナルのリクエストを再試行
        originalRequest._retry = true;
        try {
          const account =
            msalInstance.getActiveAccount() ?? msalInstance.getAllAccounts()[0];
          if (!account) {
            return Promise.reject(error);
          }
          msalInstance.setActiveAccount(account);
          // アクセストークンを取得
          const tokenResponse = await msalInstance.acquireTokenSilent({
            ...loginRequest,
            account,
          });
          // Authorizationヘッダーを差し替え
          originalRequest.headers.set(
            'Authorization',
            `Bearer ${tokenResponse.accessToken}`,
          );
          // オリジナルのリクエストを再試行
          return client(originalRequest);
        } catch (error) {
          if (error instanceof InteractionRequiredAuthError) {
            // アクセストークンの取得に失敗した場合は、ログインページを表示
            await msalInstance.loginRedirect(loginRequest);
          } else {
            console.error(`Failed to acquire token silently: ${error}`);
          }
          return Promise.reject(error);
        }
      } else if (error.response.status === 403) {
        // 403 Forbiddenの場合は、認証済みだが権限不足であるため、リクエストを再試行しない
        return Promise.reject(error);
      }

      return Promise.reject(error);
    },
  );
};

attachMsalInterceptors(graphApiClient, graphLoginRequest);
