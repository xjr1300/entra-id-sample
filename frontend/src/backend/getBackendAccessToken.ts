import {
  InteractionRequiredAuthError,
  type AccountInfo,
} from '@azure/msal-browser';
import { msalInstance } from '../msalInstance';
import { backendLoginRequest } from '.';

let inFlight: Promise<string> | null = null;

export const getBackendAccessToken = async (account: AccountInfo) => {
  if (inFlight) {
    return inFlight;
  }
  try {
    const result = await msalInstance.acquireTokenSilent({
      account,
      ...backendLoginRequest,
    });
    return result.accessToken;
  } catch (err) {
    if (err instanceof InteractionRequiredAuthError) {
      await msalInstance.acquireTokenRedirect({
        account,
        ...backendLoginRequest,
      });
    }
    throw err;
  } finally {
    inFlight = null;
  }
};
