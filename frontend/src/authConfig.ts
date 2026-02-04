import { type Configuration, type SilentRequest } from '@azure/msal-browser';

export const authConfig: Configuration = {
  auth: {
    clientId: import.meta.env.VITE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${import.meta.env.VITE_TENANT_ID}/v2.0`,
    redirectUri: import.meta.env.VITE_LOGIN_REDIRECT_URI,
    postLogoutRedirectUri: import.meta.env.VITE_LOGOUT_REDIRECT_URI,
  },
  cache: {
    // 別のタブやウィンドウでもログイン状態を共有する場合はlocalStorageを使用
    // 別のタブやウィンドウでのログイン状態を共有しない場合はsessionStorageを使用
    cacheLocation: 'localStorage',
  },
};

// Microsoft Graph API / バックエンド APIログインリクエストのスコープ設定
//
// https://learn.microsoft.com/en-us/entra/msal/javascript/browser/resources-and-scopes
// By default MSAL.js will add the openid, profile and offline_access scopes to every request.
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

    // バックエンドAPIをユーザー権限（access_as_user）で呼び出すために必要なスコープ
    `${import.meta.env.VITE_BACKEND_SCOPE}`,
  ],
};
