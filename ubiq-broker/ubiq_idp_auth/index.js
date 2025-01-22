const functions = require('@google-cloud/functions-framework');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const forge = require('node-forge');
const fs = require('fs');
const auth = require('./lib/auth')

const UBIQ_HOST = `https://api.ubiqsecurity.com`
const API_V3_ROOT = `api/v3`
const API_V0_ROOT = `api/v0`
const idp_customer_id = process.env.idp_customer_id
const idp_private_key_path = process.env.idp_private_key_path

async function generateKeyPair() {
  const { publicKey, privateKey } = await crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096, // Standard key size
    publicKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs1',
      format: 'pem'
    }
  });
  return { publicKey, privateKey };
}

async function generateCsr(publicKey, privateKey) {

  const csrDetails = [
    { name: 'commonName', value: await forge.util.encode64(forge.random.getBytesSync(18)) },
    { name: 'countryName', value: 'US' },
    { name: 'stateOrProvinceName', value: 'California' },
    { name: 'localityName', value: 'San Diego' },
    { name: 'organizationName', value: 'Ubiq Security, Inc.' },
    { shortName: 'OU', value: 'Ubiq Platform' }
  ];

  // 3. Create CSR
  csr = await forge.pki.createCertificationRequest();
  csr.publicKey = await forge.pki.publicKeyFromPem(publicKey)
  csr.setSubject = csrDetails
  await csr.sign(forge.pki.privateKeyFromPem(privateKey))
  var verified = csr.verify()

  // 4. Convert CSR to PEM format
  var pem = await forge.pki.certificationRequestToPem(csr);
  return pem
}

async function getSso(access_token, csr) {
  var options = {
    method: 'POST',
    body: JSON.stringify({ csr: csr }),
    headers: {
      Authorization: `Bearer ${access_token}`,
      Accept: 'application/json',
      'Cache-control': 'no-cache',
      "content-type": 'application/json',
    }
  }

  let response;
  try {
    let url = `${UBIQ_HOST}/${idp_customer_id}/${API_V3_ROOT}/scim/sso?self_signed=true`
    response = await fetch(url, options);

    if (response.status === 200) {
      const result = await response.json();
      return result
    } else {
      throw new Error(`Status ${response.status} (${response.statusText}) Unable to validate token ${url}`)
    }
  }
  catch (ex) {
    throw ex;
  }

}

async function decryptDataKeys(privateKey, keyDefs) {
  for (const dataset_name of Object.keys(keyDefs)) {
    const dataset = keyDefs[dataset_name];

    // Normally here we'd decrypt the encrypted private key, but we have that already!
    // encrypted_private_key isn't used in BQ so I'm not adding it to the dataset
    let pKey = forge.pki.privateKeyFromPem(privateKey);

    const unwrapped_keys = [];
    for (const key of dataset['keys']) {
      const wdk = forge.util.decode64(key);
      const decrypted = pKey.decrypt(wdk, 'RSA-OAEP');
      const rawKey = Uint8Array.from(Buffer.from(decrypted, 'binary'));
      const b64Key = forge.util.binary.base64.encode(rawKey);
      unwrapped_keys.push(b64Key);
    }
    keyDefs[dataset_name]['keys'] = unwrapped_keys;
  }
  return keyDefs
}

functions.http('ubiq_idp_auth', async (req, res) => {
  const calls = req.body.calls
  const replies = []

  for (const call of calls) {
    try {
      // Private from the keypair, stored in Google Secret Manager 
      // Should be configured as a volume on CloudRun
      // (Ubiq should have the public)
      const jwtPrivateKey = fs.readFileSync(idp_private_key_path);

      // Create the JWT that Ubiq can verify using the keypair provided during IDP setup.
      const access_token = jwt.sign({
        email: req.body.sessionUser,
        caller: req.body.caller,
        google_jwt: calls.headers.authorization,
        issuer: 'Ubiq'
      }, jwtPrivateKey, {
        algorithm: 'RS256',
        expiresIn: '10m'
      });

      // Secret Crypto Access Key is only used to encrypt/decrypt the private key.
      // We're using our own keypair so it's not needed.
      // const secret_crypto_access_key = await forge.util.encode64(forge.random.getBytesSync(33));

      // Create the Public Private Key
      const { publicKey: apiPublicKey_pem, privateKey: apiPrivateKey_pem } = await generateKeyPair()

      // Create a CSR with the keys
      const csr = await generateCsr(apiPublicKey_pem, apiPrivateKey_pem)

      // Send Ubiq the Token (who we are) and CSR (how to encode our data)
      // Get back Access and Secret from Ubiq
      const sso = await getSso(access_token, csr)
      const { public_value: access_key_id, signing_value: secret_signing_key } = sso

      // IDP Certificate to sign our requests w/Ubiq
      const idp_cert_base64 = Buffer.from(sso.api_cert).toString('base64');

      // We don't need this stuff since we're caching the data
      // If we were going to need to renew the token/cert, we would need this.
      // const x509 = new crypto.x509Certificate(sso.api_cert)
      // Set cert expiration 1 minute before actual to avoid edge case
      // const cert_expires = new Date(new Date(x509.validTo) - 60000);

      // Keys won't have an encrypted private key (because we just made the private key)
      // We don't need to decrypt it, we have it unencrypted, and encrypted_private_key isn't used in BQ

      // Fetch Def/Keys with our stuff
      const [dataset_names] = call
      const full_endpoint = `/${API_V0_ROOT}/fpe/def_keys?papi=${encodeURIComponent(access_key_id)}&ffs_name=${encodeURIComponent(dataset_names)}&payload_cert=${idp_cert_base64}`;
      const url = `${UBIQ_HOST}${full_endpoint}`
      const req_headers = auth.headers(access_key_id, secret_signing_key, full_endpoint, null, host, 'get');
      const params = {
        headers: req_headers,
        method: 'GET'
      }
      const response = await fetch(url, params)
      if (response.status === 200) {
        const data = await response.json()
        // Decrypt the data keys
        const decryptedKeys = await decryptDataKeys(apiPrivateKey_pem, data)
        replies.push(decryptedKeys)
      } else {
        const message = await response.text()
        res.send(`[UBIQ] An error occured. ${e.name}\n${e.message}\n${e.stack}`)
        return
      }
    } catch (e) {
      res.send(`[UBIQ] An error occured. ${e.name}\n${e.message}\n${e.stack}`)
      return
    }
  }

  // Reply contains decrypted data keys for enc/dec
  res.send({
    replies: replies
  })
});