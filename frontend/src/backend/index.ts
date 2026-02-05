import { type SilentRequest } from '@azure/msal-browser';

// バックエンドAPIのスコープ設定
//
// Entra IDは、1つのアクセストークンにつき、1つのリソースしか発行しない。
//
// Microsoft Graph: `https://graph.microsoft.com`
// バックエンドAPI: `api://<client-id-of-backend-api>`
//
// したがって、バックエンドAPI用のスコープは、Microsoft Graph API用のスコープとは別に定義する必要がある。
export const backendLoginRequest: SilentRequest = {
  scopes: [import.meta.env.VITE_BACKEND_SCOPE],
};
