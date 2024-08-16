const urlJoin = require('url-join');
const { ControlledContainerMixin, isURL, arrayOf } = require('@semapps/ldp');

module.exports = {
  name: 'data-grants',
  mixins: [ControlledContainerMixin],
  settings: {
    acceptedTypes: ['interop:DataGrant'],
    newResourcesPermissions: {
      anon: {
        read: true
      }
    },
    excludeFromMirror: true,
    activateTombstones: false
  },
  dependencies: ['ldp', 'ldp.registry', 'pod'],
  actions: {
    async getForApp(ctx) {
      const { appUri, podOwner } = ctx.params;

      const containerUri = await this.actions.getContainerUri({ webId: podOwner }, { parentCtx: ctx });

      let filteredContainer = await this.actions.list(
        {
          containerUri,
          filters: {
            'http://www.w3.org/ns/solid/interop#dataOwner': podOwner,
            'http://www.w3.org/ns/solid/interop#grantee': appUri
          },
          webId: 'system'
        },
        { parentCtx: ctx }
      );

      return arrayOf(filteredContainer['ldp:contains']);
    }
  },
  hooks: {
    before: {
      async post(ctx) {
        const { resource } = ctx.params;

        const webId = resource['interop:dataOwner'];
        const appUri = resource['interop:grantee'];
        const resourceType = resource['apods:registeredClass'];
        const accessMode = arrayOf(resource['interop:accessMode']);

        // Match a string of type ldp:Container
        const regex = /^([^:]+):([^:]+)$/gm;

        let ontology;
        if (isURL(resourceType)) {
          ontology = await ctx.call('ontologies.get', { uri: resourceType });
        } else if (resourceType.match(regex)) {
          const matchResults = regex.exec(resourceType);
          ontology = await ctx.call('ontologies.get', { prefix: matchResults[1] });
        } else {
          throw new Error(`Registered class must be an URI or prefixed. Received ${resourceType}`);
        }

        if (!ontology) {
          const prefix = await ctx.call('ontologies.findPrefix', { uri: resourceType });

          if (prefix) {
            const namespace = await ctx.call('ontologies.findNamespace', { prefix });

            await ctx.call('ontologies.register', { prefix, namespace });

            ontology = { prefix, namespace };
          }
        }

        if (!ontology) throw new Error(`Could not register ontology for resource type ${resourceType}`);

        // Check if containers with this type already exist (happens if another app registered the same type)
        let containersUris = await this.broker.call('type-registrations.findContainersUris', {
          type: resourceType,
          webId
        });

        // If no container exist yet, create it and register it in the TypeIndex
        if (containersUris.length === 0) {
          // Generate a path for the new container
          const containerPath = await ctx.call('ldp.container.getPath', { resourceType });
          this.logger.debug(`Automatically generated the path ${containerPath} for resource type ${resourceType}`);

          // Create the container and attach it to its parent(s)
          containersUris[0] = urlJoin(webId, 'data', containerPath);
          await ctx.call('ldp.container.createAndAttach', { containerUri: containersUris[0], webId });

          // If the resource type is invalid, an error will be thrown here
          await this.broker.call('type-registrations.register', {
            type: resourceType,
            containerUri: containersUris[0],
            webId
          });
        }

        await this.broker.call('type-registrations.bindApp', {
          type: resourceType,
          appUri,
          webId
        });

        for (const containerUri of containersUris) {
          // Give read-write permission to the application
          // For details, see https://github.com/assemblee-virtuelle/activitypods/issues/116
          await ctx.call('webacl.resource.addRights', {
            resourceUri: containerUri,
            additionalRights: {
              // Container rights
              user: {
                uri: appUri,
                read: accessMode.includes('acl:Read'),
                write: accessMode.includes('acl:Write')
              },
              // Resources default rights
              default: {
                user: {
                  uri: appUri,
                  read: accessMode.includes('acl:Read'),
                  append: accessMode.includes('acl:Append'),
                  write: accessMode.includes('acl:Write'),
                  control: accessMode.includes('acl:Control')
                }
              }
            },
            webId: 'system'
          });
        }

        // Persist the container URI so that the app doesn't need to fetch the whole TypeIndex
        ctx.params.resource['apods:registeredContainer'] = containersUris;
      }
    },
    after: {
      async delete(ctx, res) {
        const webId = res.oldData['interop:dataOwner'];
        const appUri = res.oldData['interop:grantee'];

        const containersUris = await ctx.call('type-registrations.findContainersUris', {
          type: res.oldData['apods:registeredClass'],
          webId
        });

        for (const containerUri of containersUris) {
          // If we remove a right which hasn't been granted, no error will be thrown
          await ctx.call('webacl.resource.removeRights', {
            resourceUri: containerUri,
            rights: {
              user: {
                uri: appUri,
                read: true,
                write: true
              },
              default: {
                user: {
                  uri: appUri,
                  read: true,
                  append: true,
                  write: true,
                  control: true
                }
              }
            },
            webId: 'system'
          });
        }

        return res;
      }
    }
  }
};
