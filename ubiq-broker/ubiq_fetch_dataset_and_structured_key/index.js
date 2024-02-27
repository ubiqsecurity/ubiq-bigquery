const functions = require('@google-cloud/functions-framework');
const fetch = require('node-fetch');
const auth = require('./lib/auth')

functions.http('fetch_dataset_and_structured_key', async (req, res) => {
  const calls = req.body.calls
  const replies = []
  const host = `https://api.ubiqsecurity.com`
  const endpoint = `/api/v0/fpe/def_keys`
  for (const call of calls) {
    // [dataset_name, access_key_id, secret_signing_key]
    try {
      const [dataset_names, access_key_id, secret_signing_key] = call
      const full_endpoint = `${endpoint}?papi=${encodeURIComponent(access_key_id)}&ffs_name=${encodeURIComponent(dataset_names)}`;
      const url = `${host}${full_endpoint}`
      const req_headers = auth.headers(access_key_id, secret_signing_key, full_endpoint, null, host, 'get');
      const params = {
        headers: req_headers,
        method: 'GET'
      }
      const response = await fetch(url, params)
      if (response.status === 200) {
        const data = await response.json()
        replies.push(data)
      } else {
        const message = await response.text()
        res.send(`An error occured (status: ${response.status} ${message})`)
        return
      }
    } catch (e) {
      res.send(`An error occured. ${e.name}\n${e.message}\n${e.stacktrace}`)
      return
    }
  }
  res.send({
    // request: req,
    replies: replies
  })
});