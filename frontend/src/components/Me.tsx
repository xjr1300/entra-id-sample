import { useMe } from '../hooks/backend';
import { Title, Error, NoData, Loading, Profile } from './common';

export const Me = () => {
  const { me, isLoading, error } = useMe();

  return (
    <div>
      <Title title="Me from Backend API Server" />
      <Loading isLoading={isLoading} />
      <Error message={error} />
      <NoData isExists={!!me} />
      {me && <Profile profile={me} />}
    </div>
  );
};
