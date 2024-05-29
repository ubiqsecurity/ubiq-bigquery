const functions = require('@google-cloud/functions-framework');
const fetch = require('node-fetch');
const auth = require('./lib/auth')

functions.http('ubiq_submit_events', async (req, res) => {
  const calls = req.body.calls
  const replies = []
  const host = `https://api.ubiqsecurity.com`
  const endpoint = `/api/v3/tracking/events`
  for (const call of calls) {
    // [access_key_id, secret_signing_key, usage]
    try {
      const [access_key_id, secret_signing_key, raw_events] = call
      const url = `${host}${endpoint}`
      const events = JSON.parse(raw_events)
      const formatted_events = {usage: events}
      const req_headers = auth.headers(access_key_id, secret_signing_key, endpoint, formatted_events, host, 'post');
      const params = {
        headers: req_headers,
        method: 'POST',
        body: JSON.stringify(formatted_events)
      }
      const response = await fetch(url, params)
      if (response.status === 200) {
        replies.push('Success')
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