# Security boundaries

- No private keys are stored in database schema or in-memory provenance records.
- External KMS/HSM integration is isolated behind `ExternalKeyManager`.
- Persistence uses references, hashes, commitments, proofs, and attestations instead of plaintext inputs or outputs.
- Logging flows through a redaction layer that masks sensitive payloads and plaintext values.
- Verification decisions are immutable once recorded to preserve reproducibility and auditability.
