'use strict';

const fs = require('fs');
const path = require('path');

const EXPECTED_MIDDLEWARES_PACKAGE = '@semapps/middlewares';
const EXPECTED_MIME_TYPES_PACKAGE = '@semapps/mime-types';
const PATCH_MARKER = 'APODS_ACTIVITYPUB_ACCEPT_PROFILE_NORMALIZATION_V1';

function findPackageRoot(packageName) {
  let current = path.dirname(require.resolve(packageName));
  while (current !== path.dirname(current)) {
    const packageJsonPath = path.join(current, 'package.json');
    if (fs.existsSync(packageJsonPath)) {
      const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
      if (packageJson.name === packageName) return current;
    }
    current = path.dirname(current);
  }
  throw new Error(`Could not locate ${packageName} package root`);
}

function patchMimeTypesConstants(packageRoot) {
  const filePath = path.join(packageRoot, 'constants.js');
  if (!fs.existsSync(filePath)) return;
  let source = fs.readFileSync(filePath, 'utf8');
  if (source.includes(PATCH_MARKER)) return;

  const target = `mimeFull: [MIME_TYPES.JSON, 'application/json', 'application/activity+json'],`;
  const replacement = `mimeFull: [
      MIME_TYPES.JSON,
      'application/json',
      'application/activity+json',
      'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
      'application/ld+json;profile="https://www.w3.org/ns/activitystreams"',
      'application/activity+json; profile="https://www.w3.org/ns/activitystreams"',
      'application/activity+json;profile="https://www.w3.org/ns/activitystreams"'
    ], // ${PATCH_MARKER}`;

  if (!source.includes(target)) {
    throw new Error(`[${PATCH_MARKER}] Failed to locate mimeFull target in constants.js`);
  }

  source = source.replace(target, replacement);
  fs.writeFileSync(filePath, source, 'utf8');
}

function patchMimeTypesIndex(packageRoot) {
  const filePath = path.join(packageRoot, 'index.js');
  if (!fs.existsSync(filePath)) return;
  let source = fs.readFileSync(filePath, 'utf8');
  if (source.includes(PATCH_MARKER)) return;

  const target = `  const rawNegotiatedAccept = negotiator.mediaType(availableMediaTypes);
  if (rawNegotiatedAccept !== undefined) {
    return TYPES_REPO.filter(tr => tr.mimeFull.includes(rawNegotiatedAccept))[0];
  }
  throw new MoleculerError(\`Type not supported : \${incomingType}\`, 400, 'TYPE_NOT_SUPPORTED');`;

  const replacement = `  let rawNegotiatedAccept = negotiator.mediaType(availableMediaTypes);
  if (rawNegotiatedAccept !== undefined) {
    return TYPES_REPO.filter(tr => tr.mimeFull.includes(rawNegotiatedAccept))[0];
  }
  // ${PATCH_MARKER}: Fallback - strip parameters (e.g. profile=, charset=) for robust content negotiation
  if (typeof incomingType === 'string' && incomingType.includes(';')) {
    const baseAccept = incomingType
      .split(',')
      .map(entry => entry.split(';')[0].trim())
      .filter(Boolean)
      .join(', ');
    if (baseAccept) {
      const fallbackNegotiator = new Negotiator({ headers: { accept: baseAccept } });
      rawNegotiatedAccept = fallbackNegotiator.mediaType(availableMediaTypes);
      if (rawNegotiatedAccept !== undefined) {
        return TYPES_REPO.filter(tr => tr.mimeFull.includes(rawNegotiatedAccept))[0];
      }
    }
  }
  throw new MoleculerError(\`Type not supported : \${incomingType}\`, 400, 'TYPE_NOT_SUPPORTED');`;

  if (!source.includes(target)) {
    throw new Error(`[${PATCH_MARKER}] Failed to locate negotiateType target in index.js`);
  }

  source = source.replace(target, replacement);
  fs.writeFileSync(filePath, source, 'utf8');
}

function patchMiddlewaresIndex(packageRoot) {
  const filePath = path.join(packageRoot, 'index.js');
  if (!fs.existsSync(filePath)) return;
  let source = fs.readFileSync(filePath, 'utf8');
  if (source.includes(PATCH_MARKER)) return;

  const target = `const negotiateAccept = (req, res, next) => {
  if (!req.$ctx.meta.headers)
    throw new Error(\`The parseHeader middleware must be added before the negotiateAccept middleware\`);
  if (req.$ctx.meta.headers.accept === '*/*') {
    delete req.$ctx.meta.headers.accept;
  }
  if (req.$ctx.meta.headers.accept !== undefined) {
    try {
      req.$ctx.meta.headers.accept = negotiateTypeMime(req.$ctx.meta.headers.accept);
      next();
    } catch (e) {
      next(new MoleculerError(\`Accept not supported : \${req.$ctx.meta.headers.accept}\`, 400, 'ACCEPT_NOT_SUPPORTED'));
    }
  } else {
    next();
  }
};`;

  const replacement = `const negotiateAccept = (req, res, next) => {
  if (!req.$ctx.meta.headers)
    throw new Error(\`The parseHeader middleware must be added before the negotiateAccept middleware\`);
  if (req.$ctx.meta.headers.accept === '*/*') {
    delete req.$ctx.meta.headers.accept;
  }
  if (req.$ctx.meta.headers.accept !== undefined) {
    try {
      req.$ctx.meta.headers.accept = negotiateTypeMime(req.$ctx.meta.headers.accept);
      next();
    } catch (e) {
      // ${PATCH_MARKER}: Non-GET/HEAD requests (e.g. POST to inbox/outbox) or ActivityPub profile headers should not fail Accept negotiation
      const accept = String(req.$ctx.meta.headers.accept || '');
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        req.$ctx.meta.headers.accept = MIME_TYPES.JSON;
        next();
      } else if (/application\\/(?:ld\\+json|activity\\+json|json)/i.test(accept)) {
        req.$ctx.meta.headers.accept = MIME_TYPES.JSON;
        next();
      } else {
        next(new MoleculerError(\`Accept not supported : \${req.$ctx.meta.headers.accept}\`, 400, 'ACCEPT_NOT_SUPPORTED'));
      }
    }
  } else {
    next();
  }
}; // ${PATCH_MARKER}`;

  if (!source.includes(target)) {
    throw new Error(`[${PATCH_MARKER}] Failed to locate negotiateAccept target in @semapps/middlewares index.js`);
  }

  source = source.replace(target, replacement);
  fs.writeFileSync(filePath, source, 'utf8');
}

function main() {
  try {
    const mimeTypesRoot = findPackageRoot(EXPECTED_MIME_TYPES_PACKAGE);
    patchMimeTypesConstants(mimeTypesRoot);
    patchMimeTypesIndex(mimeTypesRoot);
  } catch (err) {
    process.stderr.write(`[APODS-ACCEPT] Note: ${err.message}\n`);
  }

  try {
    const middlewaresRoot = findPackageRoot(EXPECTED_MIDDLEWARES_PACKAGE);
    patchMiddlewaresIndex(middlewaresRoot);
  } catch (err) {
    process.stderr.write(`[APODS-ACCEPT] Note: ${err.message}\n`);
  }
}

main();
