# Microsoft Entraと連携するフロントエンドの実装

このドキュメントでは、WebアプリケーションフレームワークとしてReactを使用し、Microsoft Entra（以下、Entra ID） でシングルサインオンするとともに、バックエンドのAPIを呼び出すフロントエンドを実装する方法を説明します。

Entra IDとの連携には、`MSAL（Microsoft Authentication Library）for React`を使用します。
また、HTTPクライアントとして`axios`を使用します。

フロントエンドの実装は、<https://github.com/xjr1300/entra-id-sample/tree/main/frontend>で確認できます。

なお、バックエンドではフロントエンドから `Authorization`ヘッダーに含まれるBearerトークン（アクセストークン）を検証し、適切にレスポンスを返します。
バックエンド側で認証機能の提供や、アクセストークンの管理または生成を行うことは想定していません。

## プロジェクトの作成と依存パッケージのインストール

```sh
npm create vite@latest
cd entra-id-frontend
npm install @azure/msal-browser @azure/msal-react
```

### `.env`ファイルの作成

プロジェクトルートに `.env` ファイルを作成し、以下の環境変数を設定します。

```env
VITE_CLIENT_ID=<Entra IDに登録したフロントエンド用アプリケーションのクライアントID>
VITE_TENANT_ID=<Entra IDに登録したフロントエンド用アプリケーションのテナントID>
VITE_LOGIN_REDIRECT_URI=<Entra IDに登録したフロントエンド用アプリケーションにで設定したリダイレクトURI>
VITE_LOGOUT_REDIRECT_URI=<上記で設定したリダイレクトURI>

# Microsoft Graph APIのエンドポイント
VITE_GRAPH_ME_ENDPOINT="https://graph.microsoft.com/v1.0/me"

# axiosのタイムアウト時間（ミリ秒）
VITE_AXIOS_TIMEOUT="5000"

# バックエンドAPIのベースURLとスコープ
VITE_BACKEND_API_BASE_URL = "/api"
VITE_BACKEND_SCOPE="api://<バックエンドのテナントID>/access_as_user"
```

> 実装例のため、ログアウト時のリダイレクト URIにログイン時のリダイレクト URIをそのまま使用しています。
> 必要に応じて、専用のログアウトリダイレクトURIを設定してください。

### MSALの設定

`src/authConfig.ts`ファイルを作成して、MSALの設定を記述します。

```ts
import { type Configuration, type PopupRequest } from '@azure/msal-browser';

// MSALの設定
export const authConfig: Configuration = {
  auth: {
    clientId: import.meta.env.VITE_CLIENT_ID,
    authority: `https://login.microsoftonline.com/${import.meta.env.VITE_TENANT_ID}`,
    redirectUri: import.meta.env.VITE_LOGIN_REDIRECT_URI,
    postLogoutRedirectUri: import.meta.env.VITE_LOGOUT_REDIRECT_URI,
  },
  cache: {
    // 別のタブやウィンドウでもログイン状態を共有する場合はlocalStorageを使用
    // 別のタブやウィンドウでのログイン状態を共有しない場合はsessionStorageを使用
    cacheLocation: 'localStorage',
  },
};

// ログインリクエストのスコープ
export const loginRequest: PopupRequest = {
  scopes: [
    'User.Read',    // Graph APIを呼び出すために必要なスコープ
    import.meta.env.VITE_BACKEND_SCOPE,   // バックエンドAPIを呼び出すために必要なスコープ
  ],
};
```

### MSALプロバイダーの追加

MSALプロバイダー（`MsalProvider`）をアプリケーションのルートコンポーネントに追加します。
これにより、アプリケーション全体で MSAL の機能を利用できるようになります。

* `src/main.tsx`

```ts
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { PublicClientApplication } from '@azure/msal-browser';
import { MsalProvider } from '@azure/msal-react';
import { authConfig } from './authConfig.ts';
import App from './App.tsx';

const msalInstance = new PublicClientApplication(authConfig);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <MsalProvider instance={msalInstance}>
      <App />
    </MsalProvider>
  </StrictMode>,
);
```

### SSO及びGraph API用のカスタムフック

このリポジトリには、SSOやGraph APIを呼び出す次のカスタムフックを作成してあります。

* `useAuthenticated`: `src/hooks/useAuthenticated.ts`
  * 認証状態と認証済みアカウント情報を提供します。
* `useSSO`: `src/hooks/useSSO.ts`
  * SSOに関連する状態やハンドラを提供します。
    * アカウントが認証済みかを確認中であることを示すフラグ
    * アカウントが認証済みかを示すフラグ
    * ログインハンドラ
    * アカウントを認証中であることを示すフラグ
    * ログアウトハンドラ
    * アカウントがログアウト中であることを示すフラグ
    * エラー
* `useGraphUserProfile`: `src/hooks/graph/useGraphUserProfile.ts`
  * Graph APIを呼び出して、取得したユーザープロファイルを提供します。

### バックエンドAPI呼び出し用のカスタムフック

バックエンドAPIを呼び出す次のカスタムフックを作成してあります。

* `useBackendAccessToken`: `src/hooks/backend/useBackendAccessToken.ts`
  * バックエンドAPIを呼び出すためのアクセストークンを取得する**関数**を提供します。
* `useMe`: `src/hooks/backend/useMe.ts`
  * バックエンドAPIを呼び出して、取得したユーザープロファイルを提供します。

### Appコンポーネント

上記カスタムフックを使用して、SSOログイン、SSOログアウト、ユーザープロファイルの取得およびバックエンドの呼び出しをするコンポーネントです。

`MSAL`が提供する`AuthenticatedTemplate` コンポーネントは、アカウントが認証済みの場合に、子コンポーネントをレンダリングします。
また、`UnauthenticatedTemplate` コンポーネントは、アカウントが認証されていない場合に、子コンポーネントをレンダリングします。

`App`コンポーネントに含まれる`UserProfile`コンポーネントは、フロントエンドからGraph APIを呼び出して取得したユーザープロファイルを表示します。

また、`Me`コンポーネントは、バックエンドを呼び出して取得したユーザープロファイルを表示します。
なお、フロントエンドとバックエンドは同じGraph APIを呼び出しているため、`UserProfile`コンポーネントと`Me`コンポーネントがレンダリングするユーザープロファイルは同じ内容です（つまり、同じ内容が二重にレンダリングされます）。

* `src/App.tsx`

```tsx
import {
  AuthenticatedTemplate,
  UnauthenticatedTemplate,
} from '@azure/msal-react';
import { useSSO } from './hooks';
import { UserProfile, Me } from './components';

interface ButtonProps {
  onClick: () => Promise<void>;
}
const LoginButton = ({ onClick }: ButtonProps) => {
  return <button onClick={onClick}>Login via Microsoft Entra ID</button>;
};

const LogoutButton = ({ onClick }: ButtonProps) => {
  return <button onClick={onClick}>Logout</button>;
};

const App = () => {
  const { isCheckingSSO, isLoginInProgress, login, logout, error } = useSSO();

  return (
    <>
      <h1>Entra ID SSO Sample</h1>
      {isCheckingSSO && <p>Checking SSO status...</p>}
      {isLoginInProgress && <p>Login in progress...</p>}
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}

      <AuthenticatedTemplate>
        <p>You are logged in!</p>
        <UserProfile />
        <Me />
        <LogoutButton onClick={logout} />
      </AuthenticatedTemplate>

      <UnauthenticatedTemplate>
        <p>You are not logged in.</p>
        <LoginButton onClick={login} />
      </UnauthenticatedTemplate>
    </>
  );
};

export default App;
```

## Graph用のアクセストークンの取得とGraph APIの呼び出し

`MSAL`は、アクセストークンを自動でキャッシュし、その有効期限を管理します。

```ts
const [instance] = useMsal();

const request = {
  scopes: ['User.Read'],
  account: instance.getActiveAccount(),
};

// アクセストークンを取得
const tokenResponse = await instance.acquireTokenSilent(request);
const accessToken = tokenResponse.accessToken;

// Microsoft Graph APIを呼び出す
const graphResponse = await fetch(import.meta.env.VITE_GRAPH_ME_ENDPOINT, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });
```

`acquireTokenSilent`は、キャッシュされたアクセストークンが有効な場合は、そのアクセストークンを返します。
一方、キャッシュされたアクセストークンが期限切れ、または無効な場合は、内部で再認証フローを実行し、新しいアクセストークンを取得（リフレッシュ）して返します。

このため、Graph APIやバックエンドAPIを呼び出す前に、毎回`acquireTokenSilent`を呼び出してアクセストークンを取得する実装としています。

## バックエンド用アクセストークンの取得とGraph APIの呼び出し

* `src/backend/index.ts`

バックエンド用のスコープを指定します。

```ts
import { type SilentRequest } from '@azure/msal-browser';

export const backendLoginRequest: SilentRequest = {
  scopes: [import.meta.env.VITE_BACKEND_SCOPE],
};
```

* `src/backend/getBackendAccessToken.ts`

バックエンド用のアクセストークンを取得する関数です。

```ts
import {
  InteractionRequiredAuthError,
  type AccountInfo,
} from '@azure/msal-browser';
import { msalInstance } from '../msalInstance';
import { backendLoginRequest } from '.';

let inFlight: Promise<string> | null = null;

export const getBackendAccessToken = async (account: AccountInfo) => {
  if (inFlight) {
    return inFlight;
  }
  try {
    const result = await msalInstance.acquireTokenSilent({
      account,
      ...backendLoginRequest,
    });
    return result.accessToken;
  } catch (err) {
    if (err instanceof InteractionRequiredAuthError) {
      await msalInstance.acquireTokenRedirect({
        account,
        ...backendLoginRequest,
      });
    }
    throw err;
  } finally {
    inFlight = null;
  }
};
```

* `src/hooks/backend/useBackendAccessToken.ts`

バックエンド用のアクセストークンを取得する**関数**を提供するカスタムフックです。

```ts
import { useCallback } from 'react';
import { useAuthenticated } from '../useAuthenticated';
import { getBackendAccessToken } from '../../backend/getBackendAccessToken';

export const useBackendAccessToken = () => {
  const { account } = useAuthenticated();

  const fetchAccessToken = useCallback(async (): Promise<string> => {
    if (!account) {
      throw new Error('No authenticated account found');
    }
    return await getBackendAccessToken(account);
  }, [account]);

  return { fetchAccessToken };
};
```

* `src/hooks/backend/useMe.ts`

`useBackendAccessToken`カスタムフックを使用して、バックエンドの用のアクセストークンを取得します。
その後、バックエンドの`me`エンドポイントを呼び出して、ユーザープロファイルを取得します。

```ts
import { useEffect, useState } from 'react';
import { useBackendAccessToken } from './useBackendAccessToken';
import { backendApiClient } from '../../backend/backendApiClient';
import { isProfile, type Profile } from '../../types';

export const useMe = () => {
  const [me, setMe] = useState<Profile | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const { fetchAccessToken } = useBackendAccessToken();

  useEffect(() => {
    let cancelled = false;
    fetchMe(fetchAccessToken, setMe, setError, setIsLoading, () => cancelled);
    return () => {
      cancelled = true;
    };
  }, [fetchAccessToken, setMe, setError, setIsLoading]);

  return { me, isLoading, error };
};

const fetchMe = async (
  fetchAccessToken: () => Promise<string>,
  setMe: React.Dispatch<React.SetStateAction<Profile | null>>,
  setError: React.Dispatch<React.SetStateAction<string | null>>,
  setIsLoading: React.Dispatch<React.SetStateAction<boolean>>,
  isCancelled: () => boolean,
) => {
  setIsLoading(true);
  setError(null);
  try {
    // バックエンド用のアクセストークンを取得
    const token = await fetchAccessToken();
    // バックエンドAPIの呼び出し
    const response = await backendApiClient.get('/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const data = response.data;
    if (isProfile(data)) {
      setMe(data);
    } else {
      const message = `Unexpected /me response format: ${JSON.stringify(data)}`;
      console.error(message);
      if (!isCancelled()) {
        setError(message);
      }
    }
  } catch (err) {
    const message = `Failed to fetch /me: ${JSON.stringify(err)}`;
    console.error(message);
    if (!isCancelled()) {
      setError(message);
    }
  } finally {
    if (!isCancelled()) {
      setIsLoading(false);
    }
  }
};
```

## Entra IDが発行するアクセストークン（APIごとに発行されるトークン）

Entra IDが発行するアクセストークンは、リクエスト時に指定したスコープに基づいて、**どのAPI（リソース）を呼び出すためのトークンか**が決定されます。
その結果、呼び出し対象のAPIごとに異なるアクセストークンが発行されます。

例えば、Microsoft Graph API用のアクセストークンを取得する場合は、
Microsoft Graphが定義しているスコープである`User.Read`を指定します。

次のコードで発行されるアクセストークンは、`aud（Audience）`が`https://graph.microsoft.com`となり、Microsoft Graph API専用のアクセストークンになります。

```ts
const request = {
  scopes: ['User.Read'],
  account: instance.getActiveAccount(),
};
const tokenResponse = await instance.acquireTokenSilent(request);
const accessToken = tokenResponse.accessToken;
```

一方で、バックエンドAPI用のアクセストークンを取得する場合は、バックエンドAPIとして登録したアプリケーションに対して公開したスコープを指定します。
スコープは、バックエンドAPIのアプリケーションID URIに基づく形式になります。

次のコードで発行されるアクセストークンは、`aud`がバックエンドAPIのアプリケーション（クライアント）IDとなり、そのバックエンドAPI専用のアクセストークンになります。

```ts
// <scope-name> は、access_as_userなど、バックエンドAPIで定義したスコープ名に置き換えます
const request = {
  scopes: ['api://<backend-api-app-client-id>/<scope-name>'],
  account: instance.getActiveAccount(),
};

const tokenResponse = await instance.acquireTokenSilent(request);
const accessToken = tokenResponse.accessToken;
```
