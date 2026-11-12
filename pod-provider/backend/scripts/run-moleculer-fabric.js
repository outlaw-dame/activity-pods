'use strict';

const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');
const path = require('node:path');
const { createMoleculerFabricConfig } = require('../config/moleculer-fabric');
const { assertNativeProtectedStorageReleased } =
  require('../services/utils/atproto-production-release-gate');
const { assertNotificationPgCanRun } = require('../utils/notification-pg-release-gate');

function resolveMoleculerRunner() {
  // Moleculer 0.14 exports its public package entry but does not export the
  // internal `moleculer/bin/moleculer-runner.js` subpath under Node's package
  // exports rules. Resolve the public entry first, then locate the CLI shipped
  // inside that same installed package without asking Node to resolve a blocked
  // package subpath.
  const packageEntry = require.resolve('moleculer');
  const runner = path.join(path.dirname(packageEntry), 'bin', 'moleculer-runner.js');
  if (!fs.existsSync(runner)) {
    throw new Error(`Unable to locate Moleculer runner beside public package entry: ${runner}`);
  }
  return runner;
}

function childExitCode(code, signal) {
  if (signal) {
    const signalNumber = os.constants.signals[signal];
    return Number.isInteger(signalNumber) ? 128 + signalNumber : 1;
  }
  return Number.isInteger(code) ? code : 1;
}

function run() {
  // Every official Moleculer service group must enforce the release fuse,
  // including groups that do not instantiate the triplestore service.
  assertNativeProtectedStorageReleased();
  assertNotificationPgCanRun();
  const fabric = createMoleculerFabricConfig();
  const runner = resolveMoleculerRunner();
  const args = [runner];

  if (process.argv.includes('--repl')) args.push('--repl');
  if (process.argv.includes('--hot')) args.push('--hot');
  args.push(...fabric.servicePatterns);

  process.stdout.write(
    `${JSON.stringify({
      event: 'moleculer_fabric_start',
      mode: fabric.mode,
      nodeID: fabric.nodeID,
      namespace: fabric.namespace || null,
      serviceGroup: fabric.serviceGroup,
      servicePatterns: fabric.servicePatterns
    })}\n`
  );

  const child = spawn(process.execPath, args, {
    cwd: path.resolve(__dirname, '..'),
    env: process.env,
    stdio: 'inherit'
  });

  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, () => {
      if (!child.killed) child.kill(signal);
    });
  }

  child.on('error', error => {
    console.error('Failed to start Moleculer fabric runner', error);
    process.exitCode = 1;
  });

  child.on('exit', (code, signal) => {
    // Do not re-signal this process while our SIGINT/SIGTERM handlers are
    // installed. Node suppresses the default signal termination behavior when
    // a listener exists, which can leave a launcher alive after its broker
    // child has died. Preserve conventional shell exit status instead.
    process.exitCode = childExitCode(code, signal);
  });

  return child;
}

if (require.main === module) run();

module.exports = { childExitCode, resolveMoleculerRunner, run };
