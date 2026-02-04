import {
  AuthenticatedTemplate,
  UnauthenticatedTemplate,
} from '@azure/msal-react';
import { useSSO } from './hooks';
import { UserProfile } from './components/UserProfile';

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
      <p>Entra ID SSO Sample</p>
      {isCheckingSSO && <p>Checking SSO status...</p>}
      {isLoginInProgress && <p>Login in progress...</p>}
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      <AuthenticatedTemplate>
        <p>You are logged in!</p>
        <UserProfile />
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
