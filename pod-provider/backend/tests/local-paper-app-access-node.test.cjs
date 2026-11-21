'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {randomBytes} = require('node:crypto');
const {paperAppAccess} = require('../candidates/local-paper-app-access');
const {createLocalSignupApp} = require('../candidates/local-signup-app');
const {localPodData} = require('../candidates/local-pod-data');

test('Paper checks current required SAI rights on each request', async () => {
  const app = createLocalSignupApp();
  const issuer = 'https://paper.example.org/';
  const dataset = 'claimtest-paperaccess01';
  const owner = issuer + dataset;
  const prefix = 'PREFIX i: <http://www.w3.org/ns/solid/interop#> PREFIX apods: <http://activitypods.org/ns/core#> ';
  const {user,password} = localPodData().settings;
  async function request(route, body) {
    const response = await fetch('http://127.0.0.1:3041/' + dataset + '/' + route, {
      method:'POST', redirect:'error', signal:AbortSignal.timeout(3000),
      headers:{authorization:'Basic '+Buffer.from(user+':'+password).toString('base64'),
        'X-SemappsUser':owner, 'content-type':'application/sparql-'+route, accept:'application/sparql-results+json'}, body
    });
    assert.ok(response.ok);
    return route==='query' ? (await response.json()).boolean : response.body?.cancel();
  }
  const broker = {call(action,params,options) {
    assert.equal(action,'triplestore.query');
    assert.equal(params.webId,owner);
    assert.equal(params.dataset,dataset);
    assert.equal(options.retries,0);
    return request('query',params.query);
  }};
  const check = () => paperAppAccess(broker, owner, app.appUri, issuer);
  const id = randomBytes(12).toString('hex');
  const uri = suffix => '<urn:test:'+id+':'+suffix+'>';
  const grant = uri('grant'), registration = uri('registration'), registry = uri('registry');
  const membership = `${registry} i:hasApplicationRegistration ${registration} .`;
  const required = `${grant} apods:hasSpecialRights apods:ReadGroups .`;
  const optional = `${grant} apods:hasSpecialRights apods:ReadInbox .`;
  const facts = `<${owner}> i:hasRegistrySet ${uri('set')} . ${uri('set')} i:hasAgentRegistry ${registry} .
    ${membership} ${registration} a i:ApplicationRegistration; i:registeredBy <${owner}>;
    i:registeredAgent <${app.appUri}>; i:hasAccessGrant ${grant} .
    ${grant} a i:AccessGrant; i:grantedBy <${owner}>; i:grantee <${app.appUri}>;
    i:hasAccessNeedGroup <${app.groupUri}>; apods:hasSpecialRights apods:CreateGroup, apods:ManageMembers .
    ${required} ${optional}`;
  const update = (verb,triples) => request('update',prefix+verb+' DATA { '+triples+' }');
  try {
    await update('INSERT', facts);
    assert.equal(await check(),true);
    await update('DELETE',optional);
    assert.equal(await check(),true);
    await update('DELETE',required);
    assert.equal(await check(),false);
    await update('INSERT',required);
    assert.equal(await check(),true);
    await update('DELETE',membership);
    assert.equal(await check(),false);
    await update('INSERT',membership);
    assert.equal(await check(),true);
    assert.equal(await paperAppAccess({call(){throw Error();}},owner,app.appUri,issuer),false);
    assert.equal(await paperAppAccess(broker,'https://other.example/me',app.appUri,issuer),false);
  } finally { await update('DELETE',facts); }
});
