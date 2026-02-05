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
