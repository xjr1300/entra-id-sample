import { useMsal } from '@azure/msal-react';

export const useAuthenticated = () => {
  const { accounts } = useMsal();
  const account = accounts[0] ?? null;
  const isAuthenticated = accounts.length > 0;

  return { isAuthenticated, account };
};
