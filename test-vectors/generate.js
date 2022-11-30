const jose = require('jose');
const cose = require('cose-js');
const fs = require('fs');

const credential = require('../credential.json');
const payload = new TextEncoder().encode(JSON.stringify(credential));

const privateKeyJwk = {
  "kid": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:GNcrpR6vVHCzTe7W-9ntbJx_5hHfhiVCHWHEUaC4E_c",
  "kty": "EC",
  "crv": "P-256",
  "alg": "ES256",
  "x": "51Q_KAFsFu_FOjPojMN_Nt_pWmwokjn7iF6p3LiUiuk",
  "y": "T58_jpJ03yFV3D13hACKiZpjRwXl92XZEv4Lt_OkUK4",
  "d": "bAv9YrE443mH36LnzixS3Kv5ThM5m9mH7Ab_BiU3JZc"
};


(async ()=>{

  const headers = {
    p: { kid: credential.issuer + '#key-0', alg: 'ES256', ctyp: 'application/credential+json' },
  };

  const signer = {
    key: {
      d: Buffer.from(jose.base64url.decode(privateKeyJwk.d))
    }
  };

  const verifier = {
    key: {
      x: Buffer.from(jose.base64url.decode(privateKeyJwk.x)),
      y: Buffer.from(jose.base64url.decode(privateKeyJwk.y)),
    }
  };

  const signature = await cose.sign.create(headers, payload, signer);
  const verified = await cose.sign.verify(signature, verifier, {});
  const protectedCredential = JSON.parse(new TextDecoder().decode(Buffer.from(verified)))
  // console.log(protectedCredential);
  fs.writeFileSync('../verifiable-credential.cose.base64url', jose.base64url.encode(signature));

})()