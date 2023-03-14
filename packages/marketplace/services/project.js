const { ControlledContainerMixin } = require('@semapps/ldp');
const { AnnouncerMixin } = require('@activitypods/announcer');

module.exports = {
  name: 'marketplace.offer',
  mixins: [AnnouncerMixin, ControlledContainerMixin],
  settings: {
    path: '/projects',
    acceptedTypes: ['pair:Project'],
    dereference: [],
    permissions: {},
    newResourcesPermissions: {}
  }
};
