'use strict';

// Run on the verifier workstation. Private input JSON: {privateKeyPem,scope,
// username,email}. Deliver the resulting invitation only to the approved user.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const crypto = require('node:crypto');
const { issueLocalInvitation } = require('../candidates/local-browser-signup-verifier');

async function main() {
  const [source, destination] = process.argv.slice(2);
  if (!source || !destination || process.argv.length !== 4) throw Error();
  const handle = await fs.open(source, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let bytes;
  try {
    const stat = await handle.stat();
    if (
      !stat.isFile() ||
      stat.uid !== process.getuid() ||
      (stat.mode & 0o077) !== 0 ||
      stat.size < 1 ||
      stat.size > 8192
    )
      throw Error();
    bytes = Buffer.alloc(8193);
    const result = await handle.read(bytes, 0, bytes.length, 0);
    if (result.bytesRead !== stat.size) throw Error();
    const { privateKeyPem, scope, username, email } = JSON.parse(bytes.subarray(0, result.bytesRead).toString('utf8'));
    const invitation = issueLocalInvitation({
      privateKey: crypto.createPrivateKey(privateKeyPem),
      scope,
      username,
      email
    });
    await fs.writeFile(destination, invitation + '\n', { mode: 0o600, flag: 'wx' });
  } finally {
    bytes?.fill(0);
    await handle.close();
  }
}
main().catch(() => {
  process.stderr.write(
    'Local invitation could not be issued. Check disposable flags, private input and unused output path.\n'
  );
  process.exitCode = 1;
});
