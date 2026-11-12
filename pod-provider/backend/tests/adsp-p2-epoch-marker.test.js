'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { writeEpochMarker } = require('../scripts/adsp-p2-epoch-marker');
const { readEpochMarker } = require('../scripts/adsp-p2-node-loss-removal-clock');

test('fault clock readers always receive a complete atomic epoch marker', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adsp-epoch-marker-'));
  try {
    const file = path.join(dir, 'fault-start');
    for (let i = 0; i < 100; i++) {
      const epoch = 1794447000000 + i;
      expect(writeEpochMarker(file, () => epoch)).toBe(epoch);
      expect(readEpochMarker(dir, 'fault-start')).toBe(epoch);
      expect(fs.readFileSync(file, 'utf8')).toBe(String(epoch) + '\n');
    }
    expect(fs.readdirSync(dir)).toEqual(['fault-start']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('malformed marker timestamps cannot be published', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'adsp-invalid-marker-'));
  try {
    const file = path.join(dir, 'fault-start');
    for (const value of [0, -1, NaN, Infinity, 1.5]) {
      expect(() => writeEpochMarker(file, () => value)).toThrow();
    }
    expect(fs.existsSync(file)).toBe(false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
