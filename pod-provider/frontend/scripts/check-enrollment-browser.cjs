// Run against a local frontend build with Playwright available to Node.
// All network responses are isolated fixtures for browser UI acceptance.
const { chromium } = require('playwright');
const fs = require('fs'),
  path = require('path'),
  assert = require('assert/strict');
const root = path.resolve(__dirname, '../build');
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE || undefined });
  try {
    for (const decision of ['allow', 'decline', 'lost']) {
      const page = await browser.newPage();
      const calls = [];
      page.on('pageerror', e => console.error(e.message));
      await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.pathname.endsWith('/config.js'))
          return route.fulfill({
            contentType: 'application/javascript',
            body: "window.CONFIG={BACKEND_URL:'https://login.example.test/',INSTANCE_NAME:'Local enrollment',COLOR_PRIMARY:'#222222',COLOR_SECONDARY:'#444444',INSTANCE_DESCRIPTION:{en:'Local'},AVAILABLE_LOCALES:['en'],DEFAULT_LOCALE:'en',FRONTEND_URL:'https://login.example.test/'}"
          });
        if (url.hostname !== 'login.example.test') return route.abort();
        if (url.pathname.endsWith('/status'))
          return route.fulfill({
            json: {
              state: 'awaiting_consent',
              appUri: 'https://app.example.test',
              csrfToken: 'fixture',
              requirements: { required: ['Profile'], optional: ['Photos'] }
            }
          });
        if (url.pathname.endsWith('/consent')) {
          calls.push(route.request().postDataJSON());
          if (decision === 'lost') return route.abort();
          return route.fulfill({ json: { state: decision === 'allow' ? 'consent_recorded' : 'denied' } });
        }
        const file = path.join(root, url.pathname === '/login' ? 'index.html' : url.pathname);
        if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return route.fulfill({ status: 404, body: '' });
        return route.fulfill({ path: file });
      });
      await page.goto('https://login.example.test/login?enrollment=1');
      const box = page.getByRole('checkbox', { name: 'Photos' });
      assert.equal(await box.isChecked({ timeout: 5000 }), false);
      if (decision === 'allow') await box.check();
      await page.getByRole('button', { name: decision === 'decline' ? 'Decline' : 'Allow access' }).click();
      await page
        .getByText(
          decision === 'allow'
            ? 'Your consent was recorded. Account setup is pending.'
            : decision === 'decline'
              ? 'You declined access.'
              : 'The provider could not confirm your enrollment. Reload to check its status.'
        )
        .waitFor({ timeout: 5000 });
      assert.deepEqual(calls, [
        {
          approve: decision !== 'decline',
          csrfToken: 'fixture',
          selected: decision === 'allow' ? ['Profile', 'Photos'] : decision === 'decline' ? [] : ['Profile']
        }
      ]);
      await page.close();
      console.log('PASS', decision);
    }
  } finally {
    await browser.close();
  }
})().catch(e => {
  console.error(e.message);
  process.exitCode = 1;
});
