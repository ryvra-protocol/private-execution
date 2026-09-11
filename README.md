# private-execution

Provider-independent confidential compute abstraction for RFC-0011.

## Abstraction philosophy

Core Ryvra financial logic integrates with a neutral `ConfidentialExecutionService` and `ConfidentialComputeProvider` contract instead of directly binding to any provider-specific SDK or API shape.

## Confidential execution lifecycle

1. Submit a confidential intent with immutable authority linkage.
2. Execute provider-agnostic encryption and compute.
3. Verify the normalized result commitment and provider attestation.
4. Request decryption only after verification passes.
5. Perform decryption only when verification and authorization records exist.

## Adapter model and current support

Provider | Status | Notes
--- | --- | ---
Inco | Stub adapter | Stable interface boundary, deterministic mock behavior
Arcium | Stub adapter | Stable interface boundary, deterministic mock behavior
ZK-based provider | Stub adapter | Proof-oriented normalized verification path
TEE-based provider | Stub adapter | Attestation-oriented normalized verification path

## Security constraints

- Private keys are never stored in PostgreSQL.
- External KMS/HSM boundaries are represented through `ExternalKeyManager` integration points.
- Persistence stores only references, hashes, commitments, attestations, and audit metadata.
- Sensitive values are redacted from logs by default.
- Verification must succeed before decryption can be authorized.

## RFC mapping

- RFC-0011: provider-independent confidentiality abstraction, lifecycle enforcement, provenance, and provider adapters.
- Dependency hooks: external KMS/HSM integration points are stubbed for later implementation phases.

## Project layout

- `/src/provider.js` - provider contract and capability checks
- `/src/services/confidential-execution-service.js` - lifecycle orchestration APIs
- `/src/providers/*` - provider adapter stubs
- `/src/persistence/*` - provenance store and SQL migration
- `/docs/*.md` - provider/lifecycle/security documentation
- `/test/*.test.js` - contract, lifecycle, security, and persistence tests

## Validation

Run:

```bash
npm test
```
