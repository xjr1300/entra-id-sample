import { useEffect, useState } from 'react';
import { useAuthenticated } from './index';
import { graphApiClient } from '../axios';

// ユーザープロファイル
export interface GraphUserProfile {
  id?: string | null;
  userPrincipalName?: string | null;
  displayName?: string | null;
  surname?: string | null;
  givenName?: string | null;
  jobTitle?: string | null;
  mail?: string | null;
  department?: string | null;
  officeLocation?: string | null;
  businessPhones?: string[] | null;
  mobilePhone?: string | null;
  preferredLanguage?: string | null;
}

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

export const useUserProfile = () => {
  const { isAuthenticated } = useAuthenticated();
  const [userProfile, setUserProfile] = useState<GraphUserProfile | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isAuthenticated) {
      setUserProfile(null);
      return;
    }

    let cancelled = false;
    const fetchUserProfile = async () => {
      setIsLoading(true);
      setError(null);

      try {
        const response = await graphApiClient.get(
          import.meta.env.VITE_GRAPH_ME_ENDPOINT,
        );
        const data = response.data;
        if (!isGraphUserProfile(data)) {
          console.error('Unexpected user profile format', data);
          if (!cancelled) {
            setError(
              'Microsoft Graph APIから取得したユーザープロファイルの形式が不正です。',
            );
          }
          return;
        }
        setUserProfile(data);
      } catch (err) {
        console.error('Failed to fetch user profile', err);
        if (!cancelled) {
          setError(
            'Microsoft Graph APIからユーザープロファイルを取得できませんでした。',
          );
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
        }
      }
    };

    fetchUserProfile();

    return () => {
      cancelled = true;
    };
  }, [isAuthenticated]);

  return { userProfile, isLoading, error };
};
