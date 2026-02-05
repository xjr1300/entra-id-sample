import { useGraphUserProfile } from '../hooks/graph';
import { Title, Error, NoData, Loading, Profile } from './common';

export const UserProfile = () => {
  const { userProfile, isLoading, error } = useGraphUserProfile();

  return (
    <div>
      <Title title="User Profile from Graph API" />
      <Loading isLoading={isLoading} />
      <Error message={error} />
      <NoData isExists={!!userProfile} />
      {userProfile && <Profile profile={userProfile} />}
    </div>
  );
};
