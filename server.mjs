// Local dev server: mounts the same handler as the Vercel function.
import { createServer } from 'http';
import handler from './api/agent.js';

const PORT = process.env.PORT || 8787;
const server = createServer((req, res) => {
  // Minimal Vercel-style res helpers used by the handler.
  res.status = (code) => { res.statusCode = code; return res; };
  handler(req, res).catch((e) => {
    console.error(e);
    if (!res.headersSent) { res.statusCode = 500; res.end('{"ok":false}'); }
  });
});
server.listen(PORT, () => console.log('agent listening on :' + PORT));
