const {
  OntologiesService,
  as,
  sec,
  dc,
  did,
  pair,
  void: voidOntology,
  interop,
  notify,
  oidc,
  solid,
  apods,
  pim,
  vcard
} = require('@semapps/ontologies');
const CONFIG = require('../../config/config');

module.exports = {
  // Don't specify name/dependencies - the mixin provides them
  mixins: [OntologiesService],
  settings: {
    // TODO remove pair from core ontologies
    // These are mandatory actor semantics in every Pod cell, not ephemeral
    // registrations that may land on a sibling while a replica is starting.
    // Declare them in the local ontology baseline before other services use
    // jsonld.parser/ldp.registry, including during four-cell startup.
    ontologies: [as, sec, apods, interop, notify, oidc, solid, dc, pair, vcard, pim, voidOntology, did],
    persistRegistry: true,
    settingsDataset: CONFIG.AUTH_ACCOUNTS_DATASET
  }
};
