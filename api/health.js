export default function handler(req, res) {
  return res.status(200).json({ status: 'OK', message: 'Proxy function is alive', timestamp: new Date().toISOString() });
}
