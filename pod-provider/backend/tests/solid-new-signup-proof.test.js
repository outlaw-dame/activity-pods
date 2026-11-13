'use strict';
const { verifyNewSignupSolidAuthority } =
  require('../candidates/solid-new-signup-proof');

describe('new unified signup: authoritative Solid and DID binding only', () => {
  const webId='https://pods.example/alice';
  const did='did:plc:abcdefghijklmnopqrstuvwx';
  const operationId='00000000-0000-4000-8000-000000000019';
  const input={webId,did,operationId};
  const account={'@id':'https://pods.example/auth/accounts/1',disabled:false};
  const binding={
    webId,activityPubActorId:webId,atprotoDid:did,
    atprotoSource:'local',atprotoManaged:true
  };
  const makeCall=(data={})=>jest.fn(async (name,params)=>{
    if(name==='auth.account.findByWebId'){
      expect(params).toEqual({webId});
      return Object.hasOwn(data,'account')?data.account:account;
    }
    if(name==='identitybindings.getByCanonicalAccountId'){
      expect(params).toEqual({canonicalAccountId:webId});
      return Object.hasOwn(data,'binding')?data.binding:binding;
    }
    if(name==='auth.awaitBootstrapComplete'){
      expect(params).toEqual({webId});
      return Object.hasOwn(data,'bootstrap')?data.bootstrap:{webId,complete:true};
    }
    throw new Error('Unexpected service '+name);
  });
  it('checks indexed account, exact WebID/AP/PLC binding, and real bootstrap',async()=>{
    const call=makeCall();
    await expect(verifyNewSignupSolidAuthority({...input,call}))
      .resolves.toEqual({webId,did,complete:true});
    expect(call.mock.calls.map(x=>x[0])).toEqual([
      'auth.account.findByWebId',
      'identitybindings.getByCanonicalAccountId',
      'auth.awaitBootstrapComplete'
    ]);
  });
  it.each([
    [{account:null},'SOLID_SIGNUP_PROOF_ACCOUNT_MISSING'],
    [{account:{disabled:true}},'SOLID_SIGNUP_PROOF_ACCOUNT_MISSING'],
    [{binding:null},'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH'],
    [{binding:{...binding,atprotoDid:'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb'}},
      'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH'],
    [{binding:{...binding,activityPubActorId:'https://pods.example/bob'}},
      'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH'],
    [{binding:{...binding,atprotoSource:'external'}},
      'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH'],
    [{binding:{...binding,atprotoManaged:false}},
      'SOLID_SIGNUP_PROOF_IDENTITY_MISMATCH'],
    [{bootstrap:{webId,complete:false}},'SOLID_SIGNUP_PROOF_BOOTSTRAP_INCOMPLETE'],
    [{bootstrap:{webId:'https://pods.example/bob',complete:true}},
      'SOLID_SIGNUP_PROOF_BOOTSTRAP_INCOMPLETE']
  ])('rejects missing or mismatched real account authority %#',async(data,code)=>{
    await expect(verifyNewSignupSolidAuthority({...input,call:makeCall(data)}))
      .rejects.toMatchObject({code});
  });
  it('fails closed on unavailable Solid readiness service',async()=>{
    const call=jest.fn(async()=>{throw new Error('Internal store unavailable')});
    await expect(verifyNewSignupSolidAuthority({...input,call}))
      .rejects.toMatchObject({code:'SOLID_SIGNUP_PROOF_UNAVAILABLE'});
  });
  it.each([
    { ...input,did:'did:web:pods.example' },
    { ...input,webId:'https://old:password@pods.example/alice' },
    { ...input,operationId:'' }
  ])('rejects bad verification inputs before service calls: %o',async bad=>{
    const call=jest.fn();
    await expect(verifyNewSignupSolidAuthority({...bad,call}))
      .rejects.toMatchObject({code:'SOLID_SIGNUP_PROOF_INVALID_INPUT'});
    expect(call).not.toHaveBeenCalled();
  });
});
