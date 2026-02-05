export const Title = ({ title }: { title: string }) => <h2>{title}</h2>;

export const Loading = ({ isLoading }: { isLoading: boolean }) =>
  isLoading ? <p>Loading...</p> : null;

export const Error = ({ message }: { message: string | null }) =>
  message ? <p style={{ color: 'red' }}>Error: {message}</p> : null;

export const NoData = ({ isExists }: { isExists: boolean }) =>
  !isExists ? <p>No data available.</p> : null;

export const Item = ({
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
