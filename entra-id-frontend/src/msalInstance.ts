import { PublicClientApplication } from '@azure/msal-browser';
import { authConfig } from './authConfig';

export const msalInstance = new PublicClientApplication(authConfig);
