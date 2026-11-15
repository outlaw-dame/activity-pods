import React, { useEffect, useCallback, useState } from 'react';
import { useGetIdentity, useGetList, useGetOne, useNotify, useTranslate } from 'react-admin';
import { Alert } from '@mui/material';
import { useSearchParams } from 'react-router-dom';
import { useCheckAuthenticated } from '@semapps/auth-provider';
import useTrustedApps from '../../hooks/useTrustedApps';
import useGetAppStatus from '../../hooks/useGetAppStatus';
import RegistrationScreen from './RegistrationScreen';
import UpgradeScreen from './UpgradeScreen';
import { trustedAppAuthorizationCallback } from './authorizationNavigationPolicy.mjs';

const AuthorizePage = () => {
  useCheckAuthenticated();
  const [screen, setScreen] = useState();
  const trustedApps = useTrustedApps();
  const [searchParams] = useSearchParams();
  const getAppStatus = useGetAppStatus();
  const { data: identity } = useGetIdentity();
  const notify = useNotify();
  const translate = useTranslate();

  const appUri = searchParams.get('client_id');
  const isTrustedApp = trustedApps?.some(trustedApp => trustedApp.id === appUri) || false;

  const { data: application } = useGetOne('App', { id: appUri });
  const { data: appRegistrations, isLoading } = useGetList('AppRegistration', { page: 1, perPage: Infinity });

  const accessApp = useCallback(async () => {
    try {
      // Do not follow an attacker-chosen app callback or non-HTTP scheme.
      // The authorized app descriptor and callback must share an origin.
      const redirectUrl = trustedAppAuthorizationCallback(
        application?.id,
        application?.['interop:hasAuthorizationCallbackEndpoint']
      );
      window.location.assign(redirectUrl);
    } catch {
      setScreen('error');
      notify('app.message.authorization_verification_failed', { type: 'error' });
    }
  }, [application, notify]);

  useEffect(() => {
    let cancelled = false;
    if (!isLoading && application?.id && identity?.id) {
      getAppStatus(application.id, identity).then(appStatus => {
        if (cancelled) return;
        if (!appStatus.installed) {
          setScreen('register');
        } else if (appStatus.upgradeNeeded) {
          setScreen('upgrade');
        } else {
          accessApp();
        }
      }).catch(() => {
        if (cancelled) return;
        setScreen('error');
        notify('app.message.authorization_verification_failed', { type: 'error' });
      });
    }
    return () => { cancelled = true; };
  }, [appRegistrations, isLoading, application, accessApp, getAppStatus, identity, notify]);

  switch (screen) {
    case 'error':
      return <Alert severity="error">{translate('app.message.authorization_verification_failed')}</Alert>;
    case 'register':
      return <RegistrationScreen application={application} accessApp={accessApp} isTrustedApp={isTrustedApp} />;

    case 'upgrade':
      return <UpgradeScreen application={application} accessApp={accessApp} isTrustedApp={isTrustedApp} />;

    default:
      return null;
  }
};

export default AuthorizePage;
