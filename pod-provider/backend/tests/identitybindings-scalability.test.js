const fs = require('fs');
const path = require('path');

const schema = require('../services/identitybindings.service');

const SERVICE_SOURCE = fs.readFileSync(
  path.join(__dirname, '../services/identitybindings.service.js'),
  'utf8'
);

function serviceWithMethods(overrides = {}) {
  return {
    logger: { debug: jest.fn(), warn: jest.fn() },
    ...schema.methods,
    ...overrides
  };
}

describe('identitybindings SPARQL/LDP scalability', () => {
  test('canonical reads and upserts do not preflight LDP get with resource.exist', () => {
    const getSection = SERVICE_SOURCE.slice(
      SERVICE_SOURCE.indexOf('getByCanonicalAccountId:'),
      SERVICE_SOURCE.indexOf('\n    upsert:')
    );
    const upsertSection = SERVICE_SOURCE.slice(
      SERVICE_SOURCE.indexOf('\n    upsert:'),
      SERVICE_SOURCE.indexOf('\n    upsertRepoBootstrap:')
    );

    expect(getSection).not.toContain("ldp.resource.exist");
    expect(upsertSection).not.toContain("ldp.resource.exist");
    expect(getSection).toContain('_getBindingResourceOrNull');
    expect(upsertSection).toContain('_getBindingResourceOrNull');
  });

  test('single authoritative LDP read returns null only for not-found errors', async () => {
    const get = jest.fn().mockResolvedValueOnce({ '@id': 'https://example.test/binding' });
    const service = serviceWithMethods({ actions: { get } });
    const ctx = { marker: 'parent' };

    await expect(
      service._getBindingResourceOrNull('https://example.test/binding', ctx)
    ).resolves.toEqual({ '@id': 'https://example.test/binding' });
    expect(get).toHaveBeenCalledTimes(1);
    expect(get.mock.calls[0][0]).toMatchObject({
      resourceUri: 'https://example.test/binding',
      webId: 'system'
    });
    expect(get.mock.calls[0][1]).toEqual({ parentCtx: ctx });

    get.mockRejectedValueOnce({ code: 404, type: 'NOT_FOUND' });
    await expect(
      service._getBindingResourceOrNull('https://example.test/missing', ctx)
    ).resolves.toBeNull();

    const backendFailure = Object.assign(new Error('Fuseki unavailable'), { code: 503 });
    get.mockRejectedValueOnce(backendFailure);
    await expect(
      service._getBindingResourceOrNull('https://example.test/failing', ctx)
    ).rejects.toBe(backendFailure);

    const misleadingTypeFailure = Object.assign(new Error('backend unavailable'), {
      code: 503,
      type: 'NOT_FOUND'
    });
    get.mockRejectedValueOnce(misleadingTypeFailure);
    await expect(
      service._getBindingResourceOrNull('https://example.test/failing-with-type', ctx)
    ).rejects.toBe(misleadingTypeFailure);
  });

  test('DID lookup uses a predicate/object-selective query before the type check', async () => {
    const canonicalAccountId = 'https://example.test/alice/profile/card#me';
    const ctx = {
      call: jest.fn(async (action, params) => {
        if (action === 'triplestore.query') {
          return [{ canonicalAccountId: { value: canonicalAccountId } }];
        }
        if (action === 'identitybindings.getByCanonicalAccountId') {
          return {
            canonicalAccountId,
            webId: canonicalAccountId,
            atprotoDid: 'did:plc:alice',
            atprotoHandle: 'alice.test'
          };
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const service = serviceWithMethods();

    const result = await service._findByDidWithSparql(ctx, 'did:plc:alice');

    expect(result.atprotoDid).toBe('did:plc:alice');
    const query = ctx.call.mock.calls[0][1].query;
    const selective = query.indexOf('apods:atprotoDid "did:plc:alice"');
    const typeCheck = query.indexOf('a apods:AtprotoIdentityBindingIndex');
    expect(selective).toBeGreaterThan(-1);
    expect(typeCheck).toBeGreaterThan(selective);
    expect(query).toContain('LIMIT 1');
    expect(query).not.toContain('ORDER BY');
    expect(query).not.toContain('OPTIONAL');
    expect(ctx.call).toHaveBeenCalledTimes(2);
  });

  test('selective index outage fails bounded instead of population scan, and LDP failure propagates', async () => {
    const canonicalAccountId = 'https://example.test/alice/profile/card#me';
    const queryFailure = Object.assign(new Error('settings index unavailable'), { code: 503 });
    const queryCtx = { call: jest.fn(async () => { throw queryFailure; }) };
    const service = serviceWithMethods();

    await expect(service._findByDidWithSparql(queryCtx, 'did:plc:alice'))
      .rejects.toMatchObject({ code: 503, type: 'IDENTITY_BINDING_INDEX_UNAVAILABLE' });
    expect(queryCtx.call).toHaveBeenCalledTimes(1);

    const authoritativeFailure = Object.assign(new Error('authoritative LDP unavailable'), { code: 503 });
    const authoritativeCtx = {
      call: jest.fn(async action => {
        if (action === 'triplestore.query') {
          return [{ canonicalAccountId: { value: canonicalAccountId } }];
        }
        if (action === 'identitybindings.getByCanonicalAccountId') {
          throw authoritativeFailure;
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };

    await expect(
      service._findByDidWithSparql(authoritativeCtx, 'did:plc:alice')
    ).rejects.toBe(authoritativeFailure);
  });

  test('handle lookup normalizes case and rejects a stale index projection', async () => {
    const canonicalAccountId = 'https://example.test/bob/profile/card#me';
    const ctx = {
      call: jest.fn(async (action, params) => {
        if (action === 'triplestore.query') {
          expect(params.query).toContain('apods:atprotoHandle "bob.test"');
          return [{ canonicalAccountId }];
        }
        if (action === 'identitybindings.getByCanonicalAccountId') {
          return {
            canonicalAccountId,
            webId: canonicalAccountId,
            atprotoDid: 'did:plc:bob',
            atprotoHandle: 'replacement.test'
          };
        }
        throw new Error(`Unexpected action: ${action}`);
      })
    };
    const service = serviceWithMethods();

    await expect(service._findByHandleWithSparql(ctx, 'BOB.TEST')).resolves.toBeNull();
    expect(ctx.call).toHaveBeenCalledTimes(2);
  });

  test('selective lookup escapes hostile values as SPARQL string literals', async () => {
    const hostile = 'did:plc:quote"\\newline\nvalue';
    const ctx = { call: jest.fn(async () => []) };
    const service = serviceWithMethods();

    await service._findByDidWithSparql(ctx, hostile);

    const query = ctx.call.mock.calls[0][1].query;
    expect(query).toContain(JSON.stringify(hostile));
    expect(ctx.call).toHaveBeenCalledTimes(1);
  });
});
