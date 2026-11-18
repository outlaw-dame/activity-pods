import { useEffect, useRef, useState } from 'react';
import { Button, Checkbox, FormControlLabel, Paper, Stack, Typography } from '@mui/material';
import urlJoin from 'url-join';

const messages = {
  loading: 'Loading the application’s permissions…',
  denied: 'You declined access.',
  consent_recorded: 'Your consent was recorded. Account setup is pending.',
  consent_claimed: 'The provider is checking your consent. Reload to check its status.',
  unavailable: 'The provider could not confirm your enrollment. Reload to check its status.'
};

async function request(path, body, signal) {
  const response = await fetch(urlJoin(CONFIG.BACKEND_URL, 'api/signup-enrollment', path), {
    method: 'POST',
    credentials: 'include',
    redirect: 'error',
    cache: 'no-store',
    signal,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw Error('Enrollment unavailable');
  return response.json();
}

export default function SignupConsent() {
  const [session, setSession] = useState({ state: 'loading' });
  const [selected, setSelected] = useState([]);
  const [busy, setBusy] = useState(false);
  const submitted = useRef(false);
  useEffect(() => {
    const controller = new AbortController();
    request('status', {}, AbortSignal.any([controller.signal, AbortSignal.timeout(10000)]))
      .then(result => {
        if (!controller.signal.aborted) setSession(result);
      })
      .catch(() => {
        if (!controller.signal.aborted) setSession({ state: 'unavailable' });
      });
    return () => controller.abort();
  }, []);

  const decide = async approve => {
    if (submitted.current) return;
    submitted.current = true;
    setBusy(true);
    try {
      const result = await request(
        'consent',
        {
          approve,
          csrfToken: session.csrfToken,
          selected: approve ? [...session.requirements.required, ...selected] : []
        },
        AbortSignal.timeout(35000)
      );
      setSession({ state: result.state });
    } catch {
      setSession({ state: 'unavailable' });
    }
  };

  if (session.state !== 'awaiting_consent') {
    return <Typography role="status">{messages[session.state] || messages.unavailable}</Typography>;
  }
  return (
    <Paper sx={{ p: 3, maxWidth: 520, overflowWrap: 'anywhere' }}>
      <Stack spacing={2}>
        <Typography variant="h5" component="h1">
          Review application access
        </Typography>
        <Typography>{session.appUri}</Typography>
        {session.requirements.required.map(id => (
          <Typography key={id}>Required: {id}</Typography>
        ))}
        {session.requirements.optional.map(id => (
          <FormControlLabel
            key={id}
            label={id}
            control={
              <Checkbox
                disabled={busy}
                checked={selected.includes(id)}
                onChange={(_, checked) =>
                  setSelected(previous => (checked ? [...previous, id] : previous.filter(value => value !== id)))
                }
              />
            }
          />
        ))}
        <Button variant="contained" disabled={busy} onClick={() => decide(true)}>
          Allow access
        </Button>
        <Button disabled={busy} onClick={() => decide(false)}>
          Decline
        </Button>
      </Stack>
    </Paper>
  );
}
