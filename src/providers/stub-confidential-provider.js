import { createHash } from 'node:crypto';
import { FailureReasonCode } from '../constants.js';
import { createProviderCapabilities } from '../models.js';
import { ConfidentialComputeProvider } from '../provider.js';

function hash(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export class StubConfidentialProvider extends ConfidentialComputeProvider {
  constructor(name, executionMode) {
    super(
      name,
      createProviderCapabilities({
        provider: name,
        encryption: true,
        attestation: true,
        verification: true,
        decryptionAuthorization: true,
        externalKeyManagement: true,
        deterministicVerification: true,
        executionModes: [executionMode]
      })
    );
  }

  async encrypt(input, context) {
    return {
      ciphertext: `cipher:${this.name}:${Buffer.from(JSON.stringify(input)).toString('base64url')}`,
      metadata: {
        provider: this.name,
        keyHandle: context.keyHandle,
        inputHash: hash({ input, context })
      }
    };
  }

  async compute(confidentialJob) {
    const jobMaterial = {
      provider: this.name,
      operation: confidentialJob.operation,
      ciphertext: confidentialJob.ciphertext,
      authority: confidentialJob.authority
    };
    const commitmentHash = hash(jobMaterial);
    return {
      resultCommitment: commitmentHash,
      jobRef: `${this.name}-job-${commitmentHash.slice(0, 12)}`,
      proofRef: `${this.name}-proof-${commitmentHash.slice(0, 12)}`,
      attestationRef: `${this.name}-attestation-${commitmentHash.slice(0, 12)}`,
      ciphertext: `result:${this.name}:${Buffer.from(commitmentHash).toString('base64url')}`
    };
  }

  async verify(resultCommitment, proof, policy) {
    const commitmentAligned = proof?.commitmentHash === resultCommitment;
    const policyAligned = proof?.policyHash === policy.policyHash && proof?.policyVersion === policy.policyVersion;
    return {
      pass: Boolean(commitmentAligned && policyAligned),
      reason: commitmentAligned && policyAligned ? 'Provider verification succeeded' : 'Verification artifacts did not satisfy policy binding',
      reasonCode: commitmentAligned && policyAligned ? null : FailureReasonCode.VERIFICATION_FAILED
    };
  }

  async authorizeDecrypt(request) {
    const granted = request.verificationDecision === 'PASS' && request.authorizationId === request.authority.authorizationId;
    return {
      granted,
      auditRef: `${this.name}-audit-${request.requestId}`,
      reason: granted ? 'Authorization granted' : 'Verification and authorization are required',
      reasonCode: granted ? null : FailureReasonCode.DECRYPT_NOT_AUTHORIZED
    };
  }

  async decrypt(grant, ciphertext) {
    if (!grant.granted) {
      const error = new Error('Decryption is not authorized');
      error.code = FailureReasonCode.DECRYPT_NOT_AUTHORIZED;
      throw error;
    }

    if (ciphertext.startsWith('result:')) {
      const encoded = ciphertext.split(':').at(-1);
      return Buffer.from(encoded, 'base64url').toString('utf8');
    }

    const encoded = ciphertext.split(':').at(-1);
    return Buffer.from(encoded, 'base64url').toString('utf8');
  }
}
