'use strict';

// The local dataset ticket issuer and coordinator share this fixed trust scope.
// SemApps pod-provider mode constructs the owner's WebID directly below BASE_URL.
const providerOrigin = 'https://paper.example.org';
function ownerWebId(username) {
  if (typeof username !== 'string' || !/^[a-z][a-z0-9_-]{1,31}$/u.test(username)) {
    throw new Error('Invalid disposable owner username');
  }
  return providerOrigin + '/' + username;
}
module.exports = { providerOrigin, ownerWebId };
