import type { SilentRequest } from '@azure/msal-browser';

export * from './getGraphAccessToken';
export * from './graphApiClient';

// Microsoft Graph APIのスコープ設定
//
// https://learn.microsoft.com/en-us/entra/msal/javascript/browser/resources-and-scopes
// By default MSAL.js will add the openid, profile and offline_access scopes to every request.
//
// Entra IDは、1つのアクセストークンにつき、1つのリソースしか発行しない。
//
// Microsoft Graph: `https://graph.microsoft.com`
// バックエンドAPI: `api://<client-id-of-backend-api>`
//
// したがって、Graph用のスコープは、バックエンドAPI用のスコープとは別に定義する必要がある。
//
// Graph用のスコープは、`User.Read`、`User.Read.All`など、Microsoft Graph APIで認められたスコープを複数指定できる。
export const graphLoginRequest: SilentRequest = {
  scopes: [
    /*
    // OpenID Connectに基づく認証を行い、IDトークンを取得するために必要
    'openid',

    // IDトークンにユーザーの基本的なプロファイル情報を含めるために必要
    'profile',

    // 将来、Graph APIやバックエンドAPI用のアクセストークンをユーザーの再ログインなしで取得
    // （リフレッシュ）するために必要
    'offline_access',
    */

    // Microsoft Graph APIを呼び出すために必要なOAuth 2.0スコープ
    'User.Read',
  ],
};
