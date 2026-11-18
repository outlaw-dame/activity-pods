// Local Chromium acceptance helper. The issuer supplies a fresh disposable
// session. Status and consent requests traverse real HTTP to the provider.
const { chromium } = require('playwright');
const https = require('node:https');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { once } = require('node:events');

async function startBrowserGateway() {
  const root = path.resolve(__dirname, '../../pod-provider/frontend/build');
  let endpoint;
  const server = https.createServer(
    {
      cert: fs.readFileSync(process.env.PAPER_BROWSER_TEST_CERT),
      key: fs.readFileSync(process.env.PAPER_BROWSER_TEST_KEY)
    },
    (req, res) => {
      if (
        req.method !== 'POST' ||
        !['/api/signup-enrollment/status', '/api/signup-enrollment/consent'].includes(req.url) ||
        !endpoint
      ) {
        res.writeHead(404).end();
        return;
      }
      const upstream = http.request(
        new URL(req.url, endpoint),
        {
          method: 'POST',
          headers: {
            origin: req.headers.origin || '',
            cookie: req.headers.cookie || '',
            'content-type': 'application/json'
          },
          timeout: 5000
        },
        reply => {
          res.writeHead(reply.statusCode, { 'content-type': 'application/json', 'cache-control': 'no-store' });
          reply.pipe(res);
        }
      );
      upstream.on('timeout', () => upstream.destroy());
      upstream.on('error', () => res.destroy());
      req.pipe(upstream);
    }
  );
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'https://127.0.0.1:' + server.address().port;
  return {
    origin,
    close: () => new Promise(resolve => server.close(resolve)),
    async run({ gatewayUrl, issue, required, optional }) {
      endpoint = gatewayUrl;
      const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE });
      try {
        for (const approve of [true, false]) {
          const context = await browser.newContext({ ignoreHTTPSErrors: true });
          const page = await context.newPage();
          const fixture = await issue();
          const config = {
            BACKEND_URL: origin + '/',
            INSTANCE_NAME: 'Browser acceptance',
            COLOR_PRIMARY: '#222222',
            COLOR_SECONDARY: '#444444',
            INSTANCE_DESCRIPTION: { en: 'Local' },
            AVAILABLE_LOCALES: ['en'],
            DEFAULT_LOCALE: 'en'
          };
          await page.route('**/*', async route => {
            const url = new URL(route.request().url());
            if (url.origin !== origin) return route.abort();
            if (url.pathname.startsWith('/api/signup-enrollment/')) return route.continue();
            if (url.pathname === '/config.js')
              return route.fulfill({
                contentType: 'application/javascript',
                body: 'window.CONFIG=' + JSON.stringify(config)
              });
            if (url.pathname === '/login') {
              const html = fs
                .readFileSync(path.join(root, 'index.html'), 'utf8')
                .replace(/(<script id="config-script" src=")[^"]+"/u, '$1/config.js"');
              return route.fulfill({ contentType: 'text/html', body: html, headers: { 'set-cookie': fixture.cookie } });
            }
            const file = path.resolve(root, '.' + url.pathname);
            if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile())
              return route.abort();
            return route.fulfill({ path: file });
          });
          await page.goto(origin + '/login?enrollment=1');
          await page.getByText('Required: ' + required, { exact: true }).waitFor();
          assert.equal(await page.getByRole('checkbox', { name: optional }).isChecked(), false);
          await page.getByRole('button', { name: approve ? 'Allow access' : 'Decline' }).click();
          await page
            .getByText(approve ? 'Your consent was recorded. Account setup is pending.' : 'You declined access.')
            .waitFor();
          const state = await fixture.readState();
          assert.equal(state, approve ? 'consent_recorded' : 'denied');
          await context.close();
        }
      } finally {
        await browser.close();
      }
    }
  };
}
module.exports = { startBrowserGateway };
