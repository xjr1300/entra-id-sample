import {
  InteractionRequiredAuthError,
  type SilentRequest,
} from '@azure/msal-browser';
import { msalInstance } from '../msalInstance';
import { graphLoginRequest } from '.';

let inFlight: Promise<string> | null = null;

export const getGraphAccessToken = async (): Promise<string> => {
  // すでに取得中の場合は、その`Promise`を返す
  if (inFlight) return inFlight;

  // アクセストークンをサイレントで取得
  //
  // ただし、アクセストークンを取得できず、ユーザー認証などユーザーの操作が要求される
  // 場合は、認証ページにリダイレクトするため、処理が終了する。
  // リダイレクトされると、ページが再読み込みされるため、`inFlight`は`null`になる。
  const promise = requestGraphAccessToken().finally(() => {
    inFlight = null;
  });

  inFlight = promise;
  return promise;
};

const requestGraphAccessToken = async (): Promise<string> => {
  // サインインしているアカウントを取得
  const accounts = msalInstance.getAllAccounts();
  if (accounts.length === 0) {
    throw new Error('No signed-in account');
  }
  const account = msalInstance.getActiveAccount() ?? accounts[0];
  msalInstance.setActiveAccount(account);

  // アクセストークンをサイレントで取得
  const request: SilentRequest = {
    ...graphLoginRequest,
    account,
  };
  try {
    const result = await msalInstance.acquireTokenSilent(request);
    return result.accessToken;
  } catch (err) {
    if (err instanceof InteractionRequiredAuthError) {
      // サイレントで取得できなかった場合、ユーザーを認証するページにリダイレクト
      await msalInstance.acquireTokenRedirect(request);
    }
    throw err;
  }
};
