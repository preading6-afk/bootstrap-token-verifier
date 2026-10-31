# Bootstrap Token Verifier

Python and Node.js scripts to verify ES256-signed bootstrap JWTs.

## Files

- `verify_bootstrap_token.py` — Python verifier (PyJWT + cryptography)
- `verify_bootstrap_token.js` — Node.js verifier (jsonwebtoken)
- `package.json` — Node.js dependencies

## Python

```bash
pip install pyjwt cryptography
python verify_bootstrap_token.py
```

## Node.js

```bash
npm install
node verify_bootstrap_token.js
# or
npm start
```

Both scripts verify the sample token using the embedded public JWK and print the claims if valid.

## Notes

- Algorithm is pinned to `ES256`.
- The public key is derived from the JWK (private `d` parameter removed).
- Additional claim checks (`sub`, presence of `source`/`target`) are demonstrated.
