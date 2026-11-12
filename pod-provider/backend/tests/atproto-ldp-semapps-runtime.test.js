/**
 * Check the installed SemApps version, not a copy of its service schema.
 * LdpService creates its own resource/container subservices. A hook added
 * only to our outer LDP service would leave the write actions unguarded.
 */
jest.mock('../config/config', () => ({ BASE_URL: 'https://paper.example.org/' }));
const { LdpService } = require('@semapps/ldp');
const localService = require('../services/core/ldp');

const resource = 'https://paper.example.org/alice/data/identity-bindings/managed-1';

test('installed SemApps LdpService installs our hooks on its real subservices', async () => {
  const created = [];
  const instance = {
    settings: {
      ...LdpService.settings,
      ...localService.settings,
      containers: [],
      cacher: null
    },
    schema: {
      hooksContainer: localService.hooksContainer,
      hooksResource: localService.hooksResource
    },
    broker: {
      createService: service => {
        created.push(service);
        return service;
      },
      cacher: null
    }
  };
  await LdpService.created.call(instance);
  const resourceService = created.find(s => s.mixins?.some(m => m.name === 'ldp.resource'));
  const containerService = created.find(s => s.mixins?.some(m => m.name === 'ldp.container'));
  expect(resourceService).toBeDefined();
  expect(containerService).toBeDefined();
  expect(resourceService.hooks).toBe(localService.hooksResource);
  expect(containerService.hooks).toBe(localService.hooksContainer);

  const previous = process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
  try {
    process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = 'true';
    expect(() => resourceService.hooks.before.put({
      params: { resourceUri: resource }
    })).toThrow(/Managed repository identity bindings/);
    expect(() => containerService.hooks.before.post({
      params: { containerUri: resource.replace(/managed-1$/, '') }
    })).toThrow(/Managed repository identity bindings/);
  } finally {
    if (previous === undefined) delete process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED;
    else process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED = previous;
  }
});
