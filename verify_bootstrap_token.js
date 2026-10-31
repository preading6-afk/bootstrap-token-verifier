#!/usr/bin/env node
/**
 * Verify a bootstrap JWT token signed with ES256.
 *
 * Requires: npm install jsonwebtoken
 */

import { createPublicKey } from 'node:crypto';
import jsonwebtoken from 'jsonwebtoken';

// Public JWK (private "d" parameter removed)
const PUBLIC_JWK = {
  alg: 'ES256',
  kty: 'EC',
  x: 'dxk0WKKhOyFbU0eZD0plgOB8l9rM-SD5NDgnGpvg99o',
  y: 'nIMebHLyyisqfQKkb-bCp6dVNwVqDR3FLA5ZWUZ_yQ8',
  crv: 'P-256',
};

// Example token produced by the original Node.js signer
const TOKEN =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImMwODRhODVkLWM0ODYtNDAzNS05YzYwLThjZWM4MWQ4YjhmNSJ9' +
  '.eyJqdGkiOiI0ODk5ODVkMy1hMjNlLTRjYjctYjdlNC00NWEwOTFkN2Q2ZTUiLCJzb3VyY2UiOnsiYW1vdW50IjoiMTAwLjAwIiwiYXNzZXQiOiJVU0QifSwidGFyZ2V0Ijp7ImFkZHJlc3MiOiIweGI3OTRmNWVhMGJhMzk0OTRjZTgzOTYxM2ZmZmJhNzQyNzk1NzkyNjgiLCJhc3NldCI6IkVUSCIsIm5ldHdvcmsiOiJldGhlcmV1bSIsImxhYmVsIjoiTXkgd2FsbGV0In0sInN1YiI6ImQyNTlmNmFjLTNlOGQtNDZlYi05ZTZjLWM5MmUxMzhiNzY2MCIsImlhdCI6MTc5MzQxOTU2Nn0' +
  '.D0LpwxlhdbqmLcxlP6_ZRFQKH6apG4ed7nDp0awV3DXe78nzzXvh1V66Mu2kzWSociRggxsPphWSfIaS2e83GA';

function loadPublicKey(jwk) {
  return createPublicKey({ format: 'jwk', key: jwk });
}

function verifyToken(token, publicKey) {
  // algorithms pins the allowed algorithm (security best practice)
  return jsonwebtoken.verify(token, publicKey, {
    algorithms: ['ES256'],
    // Optional extra validation you can enable:
    // subject: 'd259f6ac-3e8d-46eb-9e6c-c92e138b7660',
    // clockTolerance: 60, // seconds of leeway
    // issuer: '...',
    // audience: '...',
  });
}

function main() {
  try {
    const publicKey = loadPublicKey(PUBLIC_JWK);
    const claims = verifyToken(TOKEN, publicKey);

    console.log('Token is valid!');
    console.log('Claims:');
    console.log(JSON.stringify(claims, null, 2));

    // Example application-level checks
    const expectedSub = 'd259f6ac-3e8d-46eb-9e6c-c92e138b7660';
    if (claims.sub !== expectedSub) {
      console.log(`Warning: unexpected subject (got ${claims.sub})`);
    }

    if (!claims.source || !claims.target) {
      console.log('Warning: missing source or target claim');
    }
  } catch (err) {
    console.error('Token verification failed:', err.message);
    process.exitCode = 1;
  }
}

main();
