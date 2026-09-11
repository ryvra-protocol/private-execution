# Confidential lifecycle

The lifecycle is intentionally fail-closed:

1. Validate immutable authority linkage (`intentId`, `mandateId`, `policyVersion`, `policyHash`, `riskAssessmentId`, `authorizationId`, `correlationId`).
2. Encrypt using a provider-neutral interface plus external key handle.
3. Execute confidential compute through the selected adapter.
4. Persist provider, job reference, commitment, attestation, and audit provenance.
5. Verify result artifacts against the bound policy.
6. Request decryption only after a passing verification record exists.
7. Perform decryption only when both verification and authorization records are present and successful.

Any missing linkage, policy mismatch, or failed verification blocks decryption.
