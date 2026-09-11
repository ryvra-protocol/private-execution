# Provider interface

`ConfidentialComputeProvider` defines the provider-independent contract used by core services:

- `encrypt(input, context)` -> ciphertext and metadata
- `compute(confidentialJob)` -> result commitment, job reference, proof reference, attestation reference
- `verify(resultCommitment, proofOrAttestation, policy)` -> normalized pass/fail decision and reason
- `authorizeDecrypt(request)` -> grant/deny decision with audit reference
- `decrypt(grant, ciphertextOrResult)` -> plaintext only after authorization

Canonical models are normalized in `/src/models.js`:

- `ConfidentialIntent`
- `ConfidentialExecutionRequest`
- `ConfidentialExecutionResult`
- `VerificationResult`
- `DecryptionAuthorization`
- `ProviderCapabilities`

Current provider adapters are stable stubs for Inco, Arcium, ZK-based, and TEE-based providers.
