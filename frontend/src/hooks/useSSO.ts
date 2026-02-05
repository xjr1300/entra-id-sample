import { useState, useEffect, useCallback } from 'react';
import {
  InteractionRequiredAuthError,
  InteractionStatus,
  type AccountInfo,
  type IPublicClientApplication,
} from '@azure/msal-browser';
import { useMsal } from '@azure/msal-react';
import { graphLoginRequest } from '../authConfig.ts';
import { useAuthenticated } from './useAuthenticated.ts';
import { useAcquireToken } from './useAcquireToken.ts';

export const useSSO = () => {
  const { instance, inProgress } = useMsal();
  const { isAuthenticated, account } = useAuthenticated();
  const { acquireToken } = useAcquireToken();
  // SSOログイン状態確認中フラグ
  const [isCheckingSSO, setIsCheckingSSO] = useState(true);
  // ログイン処理中フラグ
  const [isLoginInProgress, setIsLoginInProgress] = useState(false);
  // ログアウト処理中フラグ
  const [isLogoutInProgress, setIsLogoutInProgress] = useState(false);
  // エラーメッセージ
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // このコンポーネントがアンマウントされた後に、状態を更新しないようにするためのフラグ
    // このコンポーネントがアンマウントされた後、cancelledはtrue
    const cancelled = false;
    checkSSO(inProgress, isAuthenticated, acquireToken, account).finally(() => {
      if (!cancelled) {
        setIsCheckingSSO(false);
      }
    });
  }, [instance, isAuthenticated, inProgress, acquireToken, account]);

  // ログイン
  const login = useCallback(
    () => loginFunc(instance, setIsLoginInProgress, setError),
    [instance],
  );

  // ログアウト
  const logout = useCallback(
    async () => logoutFunc(instance, setIsLogoutInProgress, setError),
    [instance],
  );

  return {
    isCheckingSSO,
    isAuthenticated,
    login,
    isLoginInProgress,
    logout,
    isLogoutInProgress,
    error,
  };
};

const checkSSO = async (
  inProgress: InteractionStatus,
  isAuthenticated: boolean,
  acquireToken: (account: AccountInfo) => Promise<string>,
  account: AccountInfo,
) => {
  // MSALが何かしている間は待機
  if (inProgress !== InteractionStatus.None) return;
  // ログインしていない場合はSSOチェックを終了
  if (!isAuthenticated) return;

  try {
    // ログインしているアカウントのトークンを取得
    await acquireToken(account);
    console.log('SSO Silent Login Succeeded');
  } catch (err) {
    // トークンを取得する際に例外が発生するのは、ログインしていない場合であり、これは無視して良いため
    // ログに記録するだけに留める
    if (err instanceof InteractionRequiredAuthError) {
      console.log('SSO Silent Login Failed - Interaction Required: ', err);
    } else {
      console.log('SSO Silent Login Failed: ', err);
    }
  }
};

const loginFunc = async (
  instance: IPublicClientApplication,
  setIsLoginInProgress: React.Dispatch<React.SetStateAction<boolean>>,
  setError: React.Dispatch<React.SetStateAction<string | null>>,
) => {
  setIsLoginInProgress(true);
  try {
    // リダイレクトによりログインページを表示
    await instance.loginRedirect({
      redirectStartPage: window.location.href,
      ...graphLoginRequest,
    });
  } catch (err) {
    console.error('Login Failed', err);
    setError(err instanceof Error ? err.message : 'ログインに失敗しました');
  } finally {
    setIsLoginInProgress(false);
  }
};

const logoutFunc = async (
  instance: IPublicClientApplication,
  setIsLogoutInProgress: React.Dispatch<React.SetStateAction<boolean>>,
  setError: React.Dispatch<React.SetStateAction<string | null>>,
) => {
  setIsLogoutInProgress(true);
  try {
    // リダイレクトによりログアウトページを表示
    await instance.logoutRedirect({
      account: instance.getActiveAccount(),
    });
  } catch (err) {
    console.error('Logout Failed', err);
    setError(err instanceof Error ? err.message : 'ログアウトに失敗しました');
  } finally {
    setIsLogoutInProgress(false);
  }
};
