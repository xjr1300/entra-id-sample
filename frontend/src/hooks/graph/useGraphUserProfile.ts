import { useEffect, useState } from 'react';
import { useAuthenticated } from '../useAuthenticated';
import { graphApiClient } from '../../graph';
import { isProfile, type Profile } from '../../types';

export const useGraphUserProfile = () => {
  const { isAuthenticated } = useAuthenticated();
  const [userProfile, setUserProfile] = useState<Profile | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;

    let cancelled = false;
    fetchUserProfile(setUserProfile, setError, setIsLoading, () => cancelled);

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  return { userProfile, isLoading, error };
};

const fetchUserProfile = async (
  setUserProfile: React.Dispatch<React.SetStateAction<Profile | null>>,
  setError: React.Dispatch<React.SetStateAction<string | null>>,
  setIsLoading: React.Dispatch<React.SetStateAction<boolean>>,
  isCancelled: () => boolean,
) => {
  setIsLoading(true);
  setError(null);

  try {
    const response = await graphApiClient.get(
      import.meta.env.VITE_GRAPH_ME_ENDPOINT,
    );
    const data = response.data;
    if (isProfile(data)) {
      setUserProfile(data);
    } else {
      const message = `Unexpected user profile format: ${JSON.stringify(data)}`;
      console.error(message);
      if (!isCancelled()) {
        setError(message);
      }
    }
  } catch (err) {
    const message = `Failed to fetch user profile: ${JSON.stringify(err)}`;
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
