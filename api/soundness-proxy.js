// api/soundness-proxy.js — Vercel Serverless Function
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Signature, X-Public-Key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const { body: requestBody, signature, publicKey } = req.body || {};
    if (!requestBody || !signature || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields', required: ['body','signature','publicKey'] });
    }
    const upstream = await fetch('https://testnet.soundness.xyz/api/proof', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Signature': signature,
        'X-Public-Key': publicKey,
        'User-Agent': 'SoundnessTUI-Proxy/1.0'
      },
      body: JSON.stringify(requestBody)
    });
    const ct = upstream.headers.get('content-type') || '';
    let data;
    if (ct.includes('application/json')) data = await upstream.json();
    else {
      const text = await upstream.text();
      data = { status: upstream.ok ? 'SUCCESS' : 'ERROR', message: text, raw_response: text };
    }
    if (!upstream.ok) {
      return res.status(upstream.status).json({
        status: 'SERVER_ERROR',
        message: 'Soundness server returned an error',
        server_status: upstream.status,
        server_response: data
      });
    }
    return res.status(200).json(data);
  } catch (err) {
    return res.status(500).json({ status: 'PROXY_ERROR', message: 'Internal proxy server error', details: err?.message || 'Unknown error' });
  }
}
