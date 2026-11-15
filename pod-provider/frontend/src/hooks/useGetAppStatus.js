import { useCallback } from 'react';
import { trustedAppStatusUrl } from '../pages/AuthorizePage/authorizationNavigationPolicy.mjs';

const useGetAppStatus = () => {
  return useCallback(async (appUri, identity) => {
    if (!identity?.id) {
      throw new Error('Authenticated Pod owner identity is required');
    }
    // Do not trust solid:oidcIssuer from editable WebID data as an
    // Authorization-bearing network destination. This helper validates
    // the owner and issuer against the configured backend origin first.
    const endpointUrl = trustedAppStatusUrl({
      backendUrl: CONFIG.BACKEND_URL,
      webId: identity.id,
      oidcIssuer: identity.webIdData?.['solid:oidcIssuer'],
      appUri
    });

    const token = localStorage.getItem('token');
    if (typeof token !== 'string' || !token) {
      throw new Error('Authenticated provider session is unavailable');
    }

    // No ambient cookies, cached private response or 3xx relay of the
    // provider bearer to a different endpoint. The service is expected
    // to return 200 directly at /.well-known/app-status.
    const response = await fetch(endpointUrl, {
      method: 'GET',
      headers: new Headers({ Authorization: `Bearer ${token}`, Accept: 'application/json' }),
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store'
    });

    if (!response.ok) {
      throw new Error('Unable to verify native application authorization status');
    }
    return await response.json();
  }, []);
};

export default useGetAppStatus;
