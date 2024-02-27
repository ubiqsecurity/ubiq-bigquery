const functions = require('@google-cloud/functions-framework');
const forge = require('node-forge');

functions.http('ubiq_decrypt_dataset_keys', async (req, res) => {
  const calls = req.body.calls
  const replies = []
  for (const call of calls) {
    try {
      const [ubiqDatasetKeyCache, secret_crypto_access_key] = call
      // Decrypt for each dataset
      for(const dataset_name of Object.keys(ubiqDatasetKeyCache)){
        const dataset = ubiqDatasetKeyCache[dataset_name];
        const encrypted_private_key = dataset["encrypted_private_key"];
        let privateKey;
        try{
          privateKey = forge.pki.decryptRsaPrivateKey(encrypted_private_key, secret_crypto_access_key);
        } catch (e){
          res.send(`[UBIQ] Failed to decrypt private key. Please check your credentials.`)
        }
        const unwrapped_keys = [];
        for(const key of dataset['keys']){
          const wdk = forge.util.decode64(key);
          const decrypted = privateKey.decrypt(wdk, 'RSA-OAEP');
          const rawKey = Uint8Array.from(Buffer.from(decrypted, 'binary'));
          const b64Key = forge.util.binary.base64.encode(rawKey);
          unwrapped_keys.push(b64Key);
        }
        ubiqDatasetKeyCache[dataset_name]['keys'] = unwrapped_keys;
      }
      replies.push(ubiqDatasetKeyCache);
    } catch (e) {
      res.send(`[UBIQ] An error occured. ${e.name}\n${e.message}\n${e.stack}`)
      return
    }
  }
  res.send({
    replies: replies
  })
});