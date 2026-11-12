'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// The removal clock waits for this file to appear and then reads its epoch.
// Publishing a partially written timestamp makes a healthy node-loss proof
// fail nondeterministically. Write in the same directory and rename atomically.
function writeEpochMarker(target, now = Date.now) {
  if (typeof target !== 'string' || !target) throw Error('Marker path required');
  const epoch = now();
  if (!Number.isSafeInteger(epoch) || epoch <= 0) {
    throw Error('Marker timestamp must be a positive safe integer');
  }
  const file = path.resolve(target);
  const temporary = path.join(
    path.dirname(file),
    '.' + path.basename(file) + '.' + process.pid + '.' +
      crypto.randomBytes(8).toString('hex') + '.tmp'
  );
  try {
    fs.writeFileSync(temporary, String(epoch) + '\n', {
      encoding: 'utf8', flag: 'wx', mode: 0o600
    });
    fs.renameSync(temporary, file);
  } finally {
    try { fs.unlinkSync(temporary); } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return epoch;
}

if (require.main === module) {
  if (process.argv.length !== 3) throw Error('Expected one barrier marker path');
  writeEpochMarker(process.argv[2]);
}

module.exports = { writeEpochMarker };
