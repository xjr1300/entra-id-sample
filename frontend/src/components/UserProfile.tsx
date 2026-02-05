import { useGraphUserProfile } from '../hooks/graph';
import { Title, Error, NoData, Loading, Item } from './common';

export const UserProfile = () => {
  const { userProfile, isLoading, error } = useGraphUserProfile();

  return (
    <div>
      <Title title="User Profile from Graph API" />
      <Loading isLoading={isLoading} />
      <Error message={error} />
      <NoData isExists={!!userProfile} />
      <Item label="ID" value={userProfile?.id} />
      <Item
        label="User Principal Name"
        value={userProfile?.userPrincipalName}
      />
      {userProfile && (
        <div>
          <Item label="Surname" value={userProfile?.surname} />
          <Item label="Given Name" value={userProfile?.givenName} />
          <Item label="Display Name" value={userProfile?.displayName} />
          <Item label="Mail" value={userProfile?.mail} />
          <Item label="Job Title" value={userProfile?.jobTitle} />
          <Item label="Department" value={userProfile?.department} />
          <Item label="Office Location" value={userProfile?.officeLocation} />
          <Item
            label="Business Phones"
            value={
              userProfile?.businessPhones &&
              userProfile.businessPhones.join(', ')
            }
          />
          <Item label="Mobile Phone" value={userProfile?.mobilePhone} />
          <Item
            label="Preferred Language"
            value={userProfile?.preferredLanguage}
          />
        </div>
      )}
    </div>
  );
};
