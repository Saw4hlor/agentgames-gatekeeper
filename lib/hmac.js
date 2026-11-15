import { createHmac, timingSafeEqual } from 'crypto';

// HMAC-SHA256 hex over the raw body — the platform's x-agent-games-signature scheme.
export function signBody(secret, rawBody) {
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

export function verifyBody(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const expected = signBody(secret, rawBody);
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(String(headerValue), 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
