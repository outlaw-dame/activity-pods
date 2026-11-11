const { ControlledContainerMixin, arrayOf } = require('@semapps/ldp');
const { MIME_TYPES } = require('@semapps/mime-types');
const { beforeSaiMutation } = require('../utils/atproto-sai-native-fence');

// Provider-owned social Group capability grants are NOT WebACL permissions
// on a person's Pod collections/files. These rights are enforced by the
// provider's collective identity service only.
const { isGroupRight, onlyGroupRights } = require('../utils/collective-special-rights');

// Never store internal mutation tokens in propagating ctx.meta or client data.
const inFlightGroupMutations = new WeakMap();
async function beginGroupMutation(ctx, resource) {
  const principal = resource['interop:grantedBy'];
  const app = resource['interop:grantee'];
  const result = await ctx.call('collective-consent-fence.begin', { principal, app });
  if (!result || result.status !== 'blocked' || typeof result.token !== 'string' ||
      !/^[0-9a-f-]{36}$/u.test(result.token)) {
    throw new Error('COLLECTIVE_CONSENT_FENCE_UNVERIFIED');
  }
  const { token } = result;
  inFlightGroupMutations.set(ctx, { principal, app, token });
}
async function finishGroupMutation(ctx) {
  const held = inFlightGroupMutations.get(ctx);
  if (!held) return;
  // A failed after-hook intentionally leaves durable pending state blocked.
  await ctx.call('collective-consent-fence.finish', held);
  inFlightGroupMutations.delete(ctx);
}

// Return true if all elements of a1 can be found on a2. Order does not matter.
const arraysEqual = (a1, a2) =>
  arrayOf(a1).length === arrayOf(a2).length && arrayOf(a1).every(i => arrayOf(a2).includes(i));

// See https://solid.github.io/data-interoperability-panel/specification/#access-authorization
module.exports = {
  name: 'access-authorizations',
  mixins: [ControlledContainerMixin],
  settings: {
    acceptedTypes: ['interop:AccessAuthorization'],
    excludeFromMirror: true,
    activateTombstones: false,
    typeIndex: 'private'
  },
  actions: {
    put() {
      throw new Error(`The resources of type interop:AccessAuthorization are immutable`);
    },
    patch() {
      throw new Error(`The resources of type interop:AccessAuthorization are immutable`);
    },
    /**
     * Generate AccessAuthorizations based on a provided list of AccessNeedGroups
     */
    async generateFromAccessNeedGroups(ctx) {
      const { accessNeedGroups, acceptedAccessNeeds, acceptedSpecialRights, podOwner, appUri } = ctx.params;
      let accessAuthorizationsUris = [];

      for (const accessNeedGroupUri of arrayOf(accessNeedGroups)) {
        const accessNeedGroup = await ctx.call('ldp.remote.get', { resourceUri: accessNeedGroupUri });
        let dataAuthorizationsUris = [];
        let specialRightsUris = [];

        if (acceptedAccessNeeds) {
          for (const accessNeedUri of arrayOf(accessNeedGroup['interop:hasAccessNeed'])) {
            if (acceptedAccessNeeds.includes(accessNeedUri)) {
              dataAuthorizationsUris.push(
                await ctx.call('data-authorizations.generateFromAccessNeed', { accessNeedUri, podOwner, appUri })
              );
            }
          }
        }

        if (acceptedSpecialRights) {
          for (const specialRightUri of arrayOf(accessNeedGroup['apods:hasSpecialRights'])) {
            if (acceptedSpecialRights.includes(specialRightUri)) {
              specialRightsUris.push(specialRightUri);
            }
          }
        }

        // Check if an access grant already exist for this AccessNeedGroup
        const accessAuthorization = await this.actions.getByAccessNeedGroup(
          { accessNeedGroupUri, podOwner },
          { parentCtx: ctx }
        );

        // Only created the corresponding AccessAuthorization if a right was granted
        if (dataAuthorizationsUris.length > 0 || specialRightsUris.length > 0) {
          if (
            accessAuthorization &&
            arraysEqual(accessAuthorization['interop:hasDataAuthorization'], dataAuthorizationsUris) &&
            arraysEqual(accessAuthorization['apods:hasSpecialRights'], specialRightsUris)
          ) {
            this.logger.info(
              `Found access authorization ${accessAuthorization.id} linked with access need group ${accessNeedGroupUri}`
            );
            accessAuthorizationsUris.push(accessAuthorization.id);
          } else {
            if (accessAuthorization) {
              this.logger.info(
                `Deleting access authorization ${accessAuthorization.id} before recreating one as it does not grant the same rights`
              );
              await this.actions.delete({ resourceUri: accessAuthorization.id, webId: podOwner });
            }
            accessAuthorizationsUris.push(
              await this.actions.post(
                {
                  resource: {
                    type: 'interop:AccessAuthorization',
                    'interop:grantedBy': podOwner,
                    'interop:grantedWith': await ctx.call('auth-agent.getResourceUri', { webId: podOwner }),
                    'interop:grantedAt': new Date().toISOString(),
                    'interop:grantee': appUri,
                    'interop:hasAccessNeedGroup': accessNeedGroupUri,
                    'interop:hasDataAuthorization': dataAuthorizationsUris,
                    'apods:hasSpecialRights': specialRightsUris
                  },
                  contentType: MIME_TYPES.JSON
                },
                { parentCtx: ctx }
              )
            );
          }
        } else if (accessAuthorization) {
          this.logger.info(
            `Deleting access authorization ${accessAuthorization.id} as no related access needs were granted`
          );
          await this.actions.delete({ resourceUri: accessAuthorization.id, webId: podOwner });
        }
      }
    },
    // Get all the AccessAuthorizations granted to an application
    async getForApp(ctx) {
      const { appUri, podOwner } = ctx.params;

      const containerUri = await this.actions.getContainerUri({ webId: podOwner }, { parentCtx: ctx });

      const filteredContainer = await this.actions.list(
        {
          containerUri,
          filters: {
            'http://www.w3.org/ns/solid/interop#grantedBy': podOwner,
            'http://www.w3.org/ns/solid/interop#grantee': appUri
          },
          webId: 'system'
        },
        { parentCtx: ctx }
      );

      return arrayOf(filteredContainer['ldp:contains']);
    },
    // Get the AccessAuthorization linked with an AccessNeedGroup
    async getByAccessNeedGroup(ctx) {
      const { accessNeedGroupUri, podOwner } = ctx.params;

      const filteredContainer = await this.actions.list(
        {
          filters: {
            'http://www.w3.org/ns/solid/interop#grantedBy': podOwner,
            'http://www.w3.org/ns/solid/interop#hasAccessNeedGroup': accessNeedGroupUri
          },
          webId: podOwner
        },
        { parentCtx: ctx }
      );

      return filteredContainer['ldp:contains']?.[0];
    },
    // Get all the special rights granted to an application
    async getSpecialRights(ctx) {
      const { appUri, podOwner } = ctx.params;

      const accessAuthorizations = await this.actions.getForApp({ appUri, podOwner }, { parentCtx: ctx });

      return accessAuthorizations.reduce((acc, cur) => {
        if (cur['apods:hasSpecialRights']) acc.push(...arrayOf(cur['apods:hasSpecialRights']));
        return acc;
      }, []);
    },
    async addPermissionsFromSpecialRights(ctx) {
      const { podOwner, appUri, specialRightsUris } = ctx.params;
      if (onlyGroupRights(specialRightsUris)) return;

      // Give read permissions on all activities, if requested
      if (specialRightsUris.includes('apods:ReadInbox') || specialRightsUris.includes('apods:ReadOutbox')) {
        await ctx.call('webacl.resource.addRights', {
          resourceUri: await ctx.call('activitypub.activity.getContainerUri', { webId: podOwner }),
          additionalRights: {
            default: {
              user: {
                uri: appUri,
                read: true
              }
            }
          },
          webId: 'system'
        });
      }

      // Give update permission on user's webId, if requested
      if (specialRightsUris.includes('apods:UpdateWebId')) {
        await ctx.call('webacl.resource.addRights', {
          resourceUri: podOwner,
          additionalRights: {
            user: {
              uri: appUri,
              write: true
            }
          },
          webId: 'system'
        });
      }

      // Give read/write permissions on all existing collections
      // plus permission to create collection, if it was requested
      await ctx.call('webacl.resource.addRights', {
        resourceUri: await ctx.call('activitypub.collection.getContainerUri', { webId: podOwner }),
        additionalRights: {
          default: {
            user: {
              uri: appUri,
              read: true,
              write: true
            }
          },
          user: specialRightsUris.includes('apods:CreateCollection')
            ? {
                uri: appUri,
                write: true
              }
            : undefined
        },
        webId: 'system'
      });

      // Give read/write permissions on the files container
      await ctx.call('webacl.resource.addRights', {
        resourceUri: await ctx.call('files.getContainerUri', { webId: podOwner }),
        additionalRights: {
          user: {
            uri: appUri,
            write: true
          },
          default: {
            user: {
              uri: appUri,
              read: true,
              write: true
            }
          }
        },
        webId: 'system'
      });
    },
    async removePermissionsFromSpecialRights(ctx) {
      const { podOwner, appUri, specialRightsUris } = ctx.params;
      if (onlyGroupRights(specialRightsUris)) return;

      // Remove read permissions on all activities, if requested
      if (specialRightsUris.includes('apods:ReadInbox') || specialRightsUris.includes('apods:ReadOutbox')) {
        await ctx.call('webacl.resource.removeRights', {
          resourceUri: await ctx.call('activitypub.activity.getContainerUri', { webId: podOwner }),
          rights: {
            default: {
              user: {
                uri: appUri,
                read: true
              }
            }
          },
          webId: 'system'
        });
      }

      // Remove update permission on user's webId, if requested
      if (specialRightsUris.includes('apods:UpdateWebId')) {
        await ctx.call('webacl.resource.removeRights', {
          resourceUri: podOwner,
          rights: {
            user: {
              uri: appUri,
              write: true
            }
          },
          webId: 'system'
        });
      }

      // Remove read/write permissions on all existing collections
      // plus permission to create collection, if it was requested
      await ctx.call('webacl.resource.removeRights', {
        resourceUri: await ctx.call('activitypub.collection.getContainerUri', { webId: podOwner }),
        rights: {
          default: {
            user: {
              uri: appUri,
              read: true,
              write: true
            }
          },
          user: specialRightsUris.includes('apods:CreateCollection')
            ? {
                uri: appUri,
                write: true
              }
            : undefined
        },
        webId: 'system'
      });

      // Remove read/write permissions on the files container
      await ctx.call('webacl.resource.removeRights', {
        resourceUri: await ctx.call('files.getContainerUri', { webId: podOwner }),
        rights: {
          default: {
            user: {
              uri: appUri,
              read: true,
              write: true
            }
          }
        },
        webId: 'system'
      });
    },
    // Delete AccessAuthorizations which are not linked to an AccessNeedGroup (may happen on app upgrade)
    async deleteOrphans(ctx) {
      const { appUri, podOwner } = ctx.params;
      const accessAuthorizations = await this.actions.getForApp({ appUri, podOwner }, { parentCtx: ctx });
      for (const accessAuthorization of accessAuthorizations) {
        try {
          await ctx.call('ldp.remote.get', { resourceUri: accessAuthorization['interop:hasAccessNeedGroup'] });
        } catch (e) {
          if (e.code === 404) {
            this.logger.info(
              `Deleting access authorization ${accessAuthorization.id} as it is not linked anymore with an existing access need group...`
            );
            await this.actions.delete({ resourceUri: accessAuthorization.id, webId: podOwner });
          } else {
            throw e;
          }
        }
      }
    }
  },
  hooks: {
    before: {
      // Pre-write barrier: a group-capability mutation must be persisted as
      // blocked BEFORE the native SAI LDP post/delete is allowed to commit.
      // This is deny-first only. There is intentionally no unsafe automatic
      // regrant until all SAI and account mutation paths are serialized.
      async post(ctx) {
        const resource = ctx.params.resource || {};
        await beforeSaiMutation(ctx, 'access-authorizations', resource, 'delete');
        if (process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED !== 'true') return;
        const rights = arrayOf(resource['apods:hasSpecialRights']);
        if (!rights.some(isGroupRight)) return;
        await beginGroupMutation(ctx, resource);
      },
      async delete(ctx) {
        const groupFenceEnabled = process.env.PROVIDER_COLLECTIVES_CONSENT_BRIDGE_ENABLED === 'true';
        const repoFenceEnabled = process.env.APODS_ATPROTO_SAI_NATIVE_FENCE_ENABLED === 'true';
        if (!groupFenceEnabled && !repoFenceEnabled) return;

        // Read the persisted authorization once for both fences. The caller
        // cannot choose which existing permissions need revocation.
        const resource = await ctx.call('access-authorizations.get', {
          resourceUri: ctx.params.resourceUri, webId: 'system'
        });
        if (repoFenceEnabled) {
          await beforeSaiMutation(ctx, 'access-authorizations', resource, 'delete');
        }
        if (groupFenceEnabled &&
            arrayOf(resource?.['apods:hasSpecialRights']).some(isGroupRight)) {
          await beginGroupMutation(ctx, resource);
        }
      }
    },
    after: {
      async post(ctx, res) {
        const podOwner = ctx.params.resource['interop:grantedBy'];

        // Attach the AccessAuthorization to the AuthorizationRegistry
        await ctx.call('auth-registry.add', {
          podOwner,
          accessAuthorizationUri: res
        });

        // For migration, we don't want this to go further
        if (ctx.meta.isMigration === true) {
          await finishGroupMutation(ctx);
          return;
        }

        // Add permissions based on the special rights
        await this.actions.addPermissionsFromSpecialRights(
          {
            podOwner,
            appUri: ctx.params.resource['interop:grantee'],
            specialRightsUris: arrayOf(ctx.params.resource['apods:hasSpecialRights'])
          },
          { parentCtx: ctx }
        );

        // Get DataGrants corresponding to DataAuthorizations
        let dataGrantsUris = [];
        for (const dataAuthorizationUri of arrayOf(ctx.params.resource['interop:hasDataAuthorization'])) {
          dataGrantsUris.push(await ctx.call('data-grants.getByDataAuthorization', { dataAuthorizationUri, podOwner }));
        }

        // Create a AccessGrant with the same data, except interop:grantedWith and interop:hasDataAuthorization
        await ctx.call('access-grants.post', {
          resource: {
            ...ctx.params.resource,
            type: 'interop:AccessGrant',
            'interop:grantedWith': undefined,
            'interop:hasDataAuthorization': undefined,
            'interop:hasDataGrant': dataGrantsUris
          },
          contentType: MIME_TYPES.JSON
        });

        await finishGroupMutation(ctx);
        return res;
      },
      // Mirror of the above hook
      async delete(ctx, res) {
        await this.actions.removePermissionsFromSpecialRights(
          {
            podOwner: res.oldData['interop:grantedBy'],
            appUri: res.oldData['interop:grantee'],
            specialRightsUris: arrayOf(res.oldData['apods:hasSpecialRights'])
          },
          { parentCtx: ctx }
        );

        // Detach the AccessAuthorization from the AuthorizationRegistry
        await ctx.call('auth-registry.remove', {
          podOwner: res.oldData['interop:grantedBy'],
          accessAuthorizationUri: res.resourceUri
        });

        // Delete AccessGrant that match the same AccessNeedGroup
        const accessGrant = await ctx.call('access-grants.getByAccessNeedGroup', {
          accessNeedGroupUri: res.oldData['interop:hasAccessNeedGroup'],
          podOwner: res.oldData['interop:grantedBy']
        });
        if (accessGrant) {
          await ctx.call('access-grants.delete', {
            resourceUri: accessGrant.id,
            webId: 'system'
          });
        }

        await finishGroupMutation(ctx);
        return res;
      }
    }
  }
};
