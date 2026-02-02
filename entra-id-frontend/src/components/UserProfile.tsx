import { useMsal } from '@azure/msal-react';
import { useUserProfile } from '../hooks';
import { useEffect } from 'react';

export const UserProfile = () => {
  const { userProfile, isLoading, error } = useUserProfile();
  const { instance, accounts } = useMsal();

  useEffect(() => {
    const fetchBackendApi = async () => {
      const scopes = [`${import.meta.env.VITE_BACKEND_SCOPE}`];
      try {
        const result = await instance.acquireTokenSilent({
          account: accounts[0],
          scopes,
        });
        console.log('Acquired token for backend API:', result.accessToken);
        const response = await fetch('/api/me', {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${result.accessToken}`,
          },
        });
        if (response.ok) {
          const data = await response.json();
          console.log('Backend API response:', data);
        } else {
          console.error('Backend API error:', response.statusText);
        }
      } catch (e) {
        console.error('Error acquiring token for backend API:', e);
      }
    };

    fetchBackendApi();
  }, [instance, accounts]);

  if (isLoading) {
    return <p>Loading user profile...</p>;
  }
  if (error) {
    return <p style={{ color: 'red' }}>Error: {error}</p>;
  }
  if (!userProfile) {
    return <p>No user profile available.</p>;
  }

  return (
    <div>
      <h2>User Profile</h2>
      <p>
        <strong>id:</strong> {userProfile.id}
      </p>
      <p>
        <strong>User Principal Name:</strong> {userProfile.userPrincipalName}
      </p>
      <p>
        <strong>Display Name:</strong> {userProfile.displayName}
      </p>
      <p>
        <strong>Surname:</strong> {userProfile.surname}
      </p>
      <p>
        <strong>Given Name:</strong> {userProfile.givenName}
      </p>
      <p>
        <strong>Job Title:</strong> {userProfile.jobTitle}
      </p>
      <p>
        <strong>Mail:</strong> {userProfile.mail}
      </p>
      <p>
        <strong>Department:</strong> {userProfile.department}
      </p>
      <p>
        <strong>Office Location:</strong> {userProfile.officeLocation}
      </p>
      <p>
        <strong>Business Phones:</strong>{' '}
        {userProfile.businessPhones && userProfile.businessPhones.join(', ')}
      </p>
      <p>
        <strong>Mobile Phone:</strong> {userProfile.mobilePhone}
      </p>
      <p>
        <strong>Preferred Language:</strong> {userProfile.preferredLanguage}
      </p>
    </div>
  );
};
