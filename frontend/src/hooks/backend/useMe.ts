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
    const token = await fetchAccessToken();
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
