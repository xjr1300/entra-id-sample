import type { Profile as ProfileType } from '../types';

export const Title = ({ title }: { title: string }) => <h2>{title}</h2>;

export const Loading = ({ isLoading }: { isLoading: boolean }) =>
  isLoading ? <p>Loading...</p> : null;

export const Error = ({ message }: { message: string | null }) =>
  message ? <p style={{ color: 'red' }}>Error: {message}</p> : null;

export const NoData = ({ isExists }: { isExists: boolean }) =>
  !isExists ? <p>No data available.</p> : null;

const Item = ({
  label,
  value,
}: {
  label: string;
  value: string | null | undefined;
}) => (
  <p>
    <strong>{label}:</strong> {value ?? 'N/A'}
  </p>
);

export const Profile = ({ profile }: { profile: ProfileType | null }) => (
  <div>
    <Item label="ID" value={profile?.id} />
    <Item label="User Principal Name" value={profile?.userPrincipalName} />
    <Item label="Surname" value={profile?.surname} />
    <Item label="Given Name" value={profile?.givenName} />
    <Item label="Display Name" value={profile?.displayName} />
    <Item label="Mail" value={profile?.mail} />
    <Item label="Job Title" value={profile?.jobTitle} />
    <Item label="Department" value={profile?.department} />
    <Item label="Office Location" value={profile?.officeLocation} />
    <Item
      label="Business Phones"
      value={profile?.businessPhones && profile.businessPhones.join(', ')}
    />
    <Item label="Mobile Phone" value={profile?.mobilePhone} />
    <Item label="Preferred Language" value={profile?.preferredLanguage} />
  </div>
);
