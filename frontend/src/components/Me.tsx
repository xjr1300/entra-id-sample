import { useMe } from '../hooks/backend';
import { Title, Error, NoData, Loading, Item } from './common';

export const Me = () => {
  const { me, isLoading, error } = useMe();

  return (
    <div>
      <Title title="Me from Backend API Server" />
      <Loading isLoading={isLoading} />
      <Error message={error} />
      <NoData isExists={!!me} />
      {me && (
        <div>
          <Item label="ID" value={me?.id} />
          <Item label="User Principal Name" value={me?.userPrincipalName} />
          <Item label="Surname" value={me?.surname} />
          <Item label="Given Name" value={me?.givenName} />
          <Item label="Display Name" value={me?.displayName} />
          <Item label="Mail" value={me?.mail} />
          <Item label="Job Title" value={me?.jobTitle} />
          <Item label="Department" value={me?.department} />
          <Item label="Office Location" value={me?.officeLocation} />
          <Item
            label="Business Phones"
            value={me?.businessPhones && me.businessPhones.join(', ')}
          />
          <Item label="Mobile Phone" value={me?.mobilePhone} />
          <Item label="Preferred Language" value={me?.preferredLanguage} />
        </div>
      )}
    </div>
  );
};
