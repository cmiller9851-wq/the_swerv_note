# Security Policy

## Authentication
Administrative access requires hardware-backed cryptographic signatures. All 
operations are verified against a secure enclave on the primary node.

## Standards
- **Encryption**: RSA-4096 / AES-256-GCM
- **Authorization**: Hardware-signature verification for all ledger changes.
