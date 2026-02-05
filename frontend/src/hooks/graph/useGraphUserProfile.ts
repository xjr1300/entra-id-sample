import { useEffect, useState } from 'react';
import { useAuthenticated } from '../useAuthenticated';
import { graphApiClient } from '../../graph';

// ユーザープロファイル
export interface GraphUserProfile {
  id?: string | null;
  userPrincipalName?: string | null;
  surname?: string | null;
  givenName?: string | null;
  displayName?: string | null;
  mail?: string | null;
  jobTitle?: string | null;
  department?: string | null;
  officeLocation?: string | null;
  businessPhones?: string[] | null;
  mobilePhone?: string | null;
  preferredLanguage?: string | null;
}

export const useGraphUserProfile = () => {
  const { isAuthenticated } = useAuthenticated();
  const [userProfile, setUserProfile] = useState<GraphUserProfile | null>(null);
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
  setUserProfile: React.Dispatch<React.SetStateAction<GraphUserProfile | null>>,
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
    if (isGraphUserProfile(data)) {
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

// GraphUserProfile型ガード
export const isGraphUserProfile = (obj: unknown): obj is GraphUserProfile => {
  if (typeof obj != 'object' || obj === null) return false;
  const instance = obj as GraphUserProfile;
  if (instance.id != null && typeof instance.id !== 'string') return false;
  if (
    instance.userPrincipalName != null &&
    typeof instance.userPrincipalName !== 'string'
  )
    return false;
  if (instance.displayName != null && typeof instance.displayName !== 'string')
    return false;
  if (instance.surname != null && typeof instance.surname !== 'string')
    return false;
  if (instance.givenName != null && typeof instance.givenName !== 'string')
    return false;
  if (instance.jobTitle != null && typeof instance.jobTitle !== 'string')
    return false;
  if (instance.mail != null && typeof instance.mail !== 'string') return false;
  if (instance.department != null && typeof instance.department !== 'string')
    return false;
  if (
    instance.officeLocation != null &&
    typeof instance.officeLocation !== 'string'
  )
    return false;
  if (instance.businessPhones != null) {
    if (!Array.isArray(instance.businessPhones)) return false;
    for (const phone of instance.businessPhones) {
      if (typeof phone !== 'string') return false;
    }
  }
  if (instance.mobilePhone != null && typeof instance.mobilePhone !== 'string')
    return false;
  if (
    instance.preferredLanguage != null &&
    typeof instance.preferredLanguage !== 'string'
  )
    return false;
  return true;
};
