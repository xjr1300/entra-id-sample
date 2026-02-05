import { useEffect, useState } from 'react';
import { useBackendAccessToken } from './useBackendAccessToken';
import { backendApiClient } from '../../backend/backendApiClient';

export const useMe = () => {
  const [me, setMe] = useState<Me | null>(null);
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
  setMe: React.Dispatch<React.SetStateAction<Me | null>>,
  setError: React.Dispatch<React.SetStateAction<string | null>>,
  setIsLoading: React.Dispatch<React.SetStateAction<boolean>>,
  isCancelled: () => boolean,
) => {
  setIsLoading(true);
  setError(null);
  try {
    const token = await fetchAccessToken();
    const response = await backendApiClient.get<Me>('/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    const data = response.data;
    if (isMe(data)) {
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

export interface Me {
  id: string;
  userPrincipalName?: string | null;
  surname?: string | null;
  givenName?: string | null;
  displayName?: string | null;
  mail?: string | null;
  jobTitle?: string | null;
  department?: string | null;
  officeLocation?: string | null;
  businessPhones?: string[] | null;
  mobilePhone: string | null;
  preferredLanguage: string | null;
}

const isMe = (obj: unknown): obj is Me => {
  if (typeof obj !== 'object' || obj === null) return false;
  const instance = obj as Me;
  if (typeof instance.id !== 'string') return false;
  if (
    instance.userPrincipalName != null &&
    typeof instance.userPrincipalName !== 'string'
  )
    return false;
  if (instance.surname != null && typeof instance.surname !== 'string')
    return false;
  if (instance.givenName != null && typeof instance.givenName !== 'string')
    return false;
  if (instance.displayName != null && typeof instance.displayName !== 'string')
    return false;
  if (instance.mail != null && typeof instance.mail !== 'string') return false;
  if (instance.jobTitle != null && typeof instance.jobTitle !== 'string')
    return false;
  if (instance.department != null && typeof instance.department !== 'string')
    return false;
  if (
    instance.officeLocation != null &&
    typeof instance.officeLocation !== 'string'
  )
    return false;
  if (
    instance.businessPhones != null &&
    !Array.isArray(instance.businessPhones)
  )
    return false;
  return true;
};
