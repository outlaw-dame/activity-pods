import React, { useEffect, useState } from 'react';
import { useCheckAuthenticated } from '@semapps/auth-provider';
import { useTranslate, useGetList, useAuthProvider, useNotify, useCreatePath, useGetIdentity } from 'react-admin';
import { Box, Typography, List } from '@mui/material';
import { CopyToClipboard } from 'react-copy-to-clipboard';
import { useNavigate } from 'react-router-dom';
import EmailIcon from '@mui/icons-material/Email';
import PersonIcon from '@mui/icons-material/Person';
import PlaceIcon from '@mui/icons-material/Place';
import LockIcon from '@mui/icons-material/Lock';
import LinkIcon from '@mui/icons-material/Link';
import TuneIcon from '@mui/icons-material/Tune';
import ArrowForwardIosIcon from '@mui/icons-material/ArrowForwardIos';
import FileCopyIcon from '@mui/icons-material/FileCopy';
import useContactLink from '../../hooks/useContactLink';
import SettingsItem from './SettingsItem';

const SettingsPage = () => {
  useCheckAuthenticated();
  const translate = useTranslate();
  const authProvider = useAuthProvider();
  const navigate = useNavigate();
  const { data: identity } = useGetIdentity();
  const createPath = useCreatePath();
  const notify = useNotify();
  const [accountSettings, setAccountSettings] = useState({});

  const { data } = useGetList('Location');
  const contactLink = useContactLink();

  useEffect(() => {
    authProvider.getAccountSettings().then(res => setAccountSettings(res));
  }, [setAccountSettings, authProvider]);

  return (
    <>
      <Typography variant="h2" component="h1" noWrap sx={{ mt: 2 }}>
        {translate('app.page.settings')}
      </Typography>
      <Box>
        <List>
          <SettingsItem
            onClick={() => navigate(createPath({ resource: 'Profile', id: identity?.profileData?.id, type: 'edit' }))}
            icon={<PersonIcon />}
            label="app.setting.profile"
            value={identity?.fullName}
          />
          <SettingsItem
            onClick={() => navigate('/Location')}
            icon={<PlaceIcon />}
            label="app.setting.addresses"
            value={translate('app.setting.address', { smart_count: data ? data.length : 0 })}
          />
          <SettingsItem
            onClick={() => navigate('/settings/email')}
            icon={<EmailIcon />}
            label="app.setting.email"
            value={accountSettings.email}
          />
          <SettingsItem
            onClick={() => navigate('/settings/password')}
            icon={<LockIcon />}
            label="app.setting.password"
            value="***************"
          />
          <CopyToClipboard text={contactLink}>
            <SettingsItem
              onClick={() => notify('app.notification.contact_link_copied', { type: 'success' })}
              icon={<LinkIcon />}
              label="app.card.share_contact"
              value={contactLink}
              actionIcon={<FileCopyIcon />}
            />
          </CopyToClipboard>
          <SettingsItem
            onClick={() => navigate('/settings/advanced')}
            icon={<TuneIcon />}
            label="app.page.settings_advanced"
            actionIcon={<ArrowForwardIosIcon />}
          />
        </List>
      </Box>
    </>
  );
};

export default SettingsPage;