import { randomUUID } from 'node:crypto';
import { ExecutionStatus, FailureReasonCode, REQUIRED_AUTHORITY_FIELDS } from '../constants.js';
import {
  createConfidentialExecutionRequest,
  createConfidentialExecutionResult,
  createConfidentialIntent,
  createDecryptionAuthorization,
  createVerificationResult,
  validateAuthorityLinkage
} from '../models.js';
import { assertProviderContract } from '../provider.js';
import { MemoryLogger } from '../security/redaction.js';
import { NoopExternalKeyManager } from '../security/key-manager.js';

function linkageError(reason) {
  const error = new Error(reason);
  error.code = FailureReasonCode.MISSING_AUTHORITY_LINKAGE;
  return error;
}

function verifyAuthorityLinkage(linkage) {
  try {
    return validateAuthorityLinkage(linkage);
  } catch {
    throw linkageError('Authority linkage is required and must be immutable');
  }
}

export class ConfidentialExecutionService {
  constructor({ providers, store, logger = new MemoryLogger(), keyManager = new NoopExternalKeyManager() }) {
    this.providers = new Map(Object.entries(providers ?? {}));
    this.store = store;
    this.logger = logger;
    this.keyManager = keyManager;

    for (const provider of this.providers.values()) {
      assertProviderContract(provider);
    }
  }

  getProviderCapabilities(providerName) {
    return this.getProvider(providerName).getCapabilities();
  }

  getProvider(providerName) {
    const provider = this.providers.get(providerName);
    if (!provider) {
      const error = new Error(`Unknown provider: ${providerName}`);
      error.code = FailureReasonCode.PROVIDER_UNAVAILABLE;
      throw error;
    }
    return provider;
  }

  async SubmitConfidentialIntent(intentLike) {
    const intent = createConfidentialIntent(intentLike);
    this.store.saveIntent(intent);
    this.logger.info('confidential.intent.submitted', intent);
    return intent;
  }

  async ExecuteConfidentialCompute(requestLike) {
    const request = createConfidentialExecutionRequest(requestLike);
    const authority = verifyAuthorityLinkage(request);
    const provider = this.getProvider(request.provider);
    const keyHandle = await this.keyManager.resolveKeyHandle(provider.name, authority);

    const encrypted = await provider.encrypt(request.payload, { keyHandle, intentId: request.intentId, correlationId: request.correlationId });
    const computed = await provider.compute({
      operation: request.operation,
      ciphertext: encrypted.ciphertext,
      authority,
      metadata: request.metadata
    });

    this.store.saveRequest(request);
    this.store.saveInput({
      id: randomUUID(),
      confidentialJobId: request.id,
      inputRef: request.inputRef,
      ciphertextRef: encrypted.ciphertext,
      inputHash: encrypted.metadata.inputHash
    });
    this.store.saveJob({
      id: request.id,
      intentId: request.intentId,
      mandateId: request.mandateId,
      authorizationId: request.authorizationId,
      correlationId: request.correlationId,
      provider: request.provider,
      providerJobRef: computed.jobRef,
      operation: request.operation,
      status: ExecutionStatus.EXECUTED
    });
    this.store.saveProviderAttestation({
      id: randomUUID(),
      confidentialJobId: request.id,
      provider: request.provider,
      proofRef: computed.proofRef,
      attestationRef: computed.attestationRef
    });

    const result = createConfidentialExecutionResult({
      confidentialJobId: request.id,
      requestId: request.id,
      provider: request.provider,
      jobRef: computed.jobRef,
      commitmentHash: computed.resultCommitment,
      resultCiphertextRef: computed.ciphertext,
      proofRef: computed.proofRef,
      attestationRef: computed.attestationRef,
      metadata: { status: ExecutionStatus.EXECUTED }
    });

    this.store.saveResult(result);
    this.logger.info('confidential.compute.executed', {
      requestId: request.id,
      provider: request.provider,
      payload: request.payload,
      commitmentHash: result.commitmentHash
    });

    return Object.freeze({ ...result, ciphertext: computed.ciphertext, authority });
  }

  async VerifyConfidentialResult({ requestId, policy, actorRef }) {
    const request = this.store.getRequest(requestId);
    const result = this.store.getResult(requestId);

    if (!request || !result) {
      throw new Error(`Unknown request: ${requestId}`);
    }

    verifyAuthorityLinkage(request);
    if (policy.policyHash !== request.policyHash || policy.policyVersion !== request.policyVersion) {
      const verification = createVerificationResult({
        confidentialJobId: requestId,
        requestId,
        provider: request.provider,
        decision: 'FAIL',
        reasonCode: FailureReasonCode.POLICY_MISMATCH,
        reason: 'Policy binding mismatch',
        commitmentHash: result.commitmentHash,
        proofRef: result.proofRef,
        attestationRef: result.attestationRef,
        policyVersion: policy.policyVersion,
        policyHash: policy.policyHash,
        verifier: 'service',
        actorRef
      });
      this.store.saveVerification(verification);
      return verification;
    }

    const provider = this.getProvider(request.provider);
    const providerResult = await provider.verify(
      result.commitmentHash,
      { proofRef: result.proofRef, attestationRef: result.attestationRef, policyHash: request.policyHash, policyVersion: request.policyVersion },
      policy
    );

    const verification = createVerificationResult({
      confidentialJobId: requestId,
      requestId,
      provider: request.provider,
      decision: providerResult.pass ? 'PASS' : 'FAIL',
      reasonCode: providerResult.reasonCode,
      reason: providerResult.reason,
      commitmentHash: result.commitmentHash,
      proofRef: result.proofRef,
      attestationRef: result.attestationRef,
      policyVersion: policy.policyVersion,
      policyHash: policy.policyHash,
      verifier: 'service',
      actorRef
    });

    this.store.saveVerification(verification);
    this.logger.info('confidential.result.verified', verification);
    return verification;
  }

  async RequestDecryption({ requestId, actorRef }) {
    const request = this.store.getRequest(requestId);
    const result = this.store.getResult(requestId);
    const verification = this.store.getVerification(requestId);

    if (!request || !result || !verification) {
      const error = new Error('Verification record is required before decryption');
      error.code = FailureReasonCode.DECRYPT_NOT_AUTHORIZED;
      throw error;
    }

    if (verification.decision !== 'PASS') {
      const denied = createDecryptionAuthorization({
        confidentialJobId: requestId,
        requestId,
        verificationId: verification.id,
        authorizationId: request.authorizationId,
        granted: false,
        auditRef: `audit-${requestId}`,
        actorRef,
        reasonCode: FailureReasonCode.DECRYPT_NOT_AUTHORIZED,
        reason: 'Verification must pass before authorization'
      });
      this.store.saveDecryptionAuthorization(denied);
      return denied;
    }

    const provider = this.getProvider(request.provider);
    const decision = await provider.authorizeDecrypt({
      requestId,
      verificationDecision: verification.decision,
      authorizationId: request.authorizationId,
      authority: verifyAuthorityLinkage(request)
    });

    const authorization = createDecryptionAuthorization({
      confidentialJobId: requestId,
      requestId,
      verificationId: verification.id,
      authorizationId: request.authorizationId,
      granted: decision.granted,
      auditRef: decision.auditRef,
      actorRef,
      reasonCode: decision.reasonCode,
      reason: decision.reason
    });

    this.store.saveDecryptionAuthorization(authorization);
    this.logger.info('confidential.decrypt.authorized', authorization);
    return authorization;
  }

  async PerformDecryption({ requestId }) {
    const request = this.store.getRequest(requestId);
    const verification = this.store.getVerification(requestId);
    const authorization = this.store.getDecryptionAuthorization(requestId);
    const result = this.store.getResult(requestId);

    if (!request || !result || !verification || !authorization) {
      const error = new Error('Verification record and authorization are required');
      error.code = FailureReasonCode.DECRYPT_NOT_AUTHORIZED;
      throw error;
    }

    if (verification.decision !== 'PASS' || !authorization.granted) {
      const error = new Error('Decryption is not authorized');
      error.code = FailureReasonCode.DECRYPT_NOT_AUTHORIZED;
      throw error;
    }

    const provider = this.getProvider(request.provider);
    const plaintext = await provider.decrypt(authorization, result.resultCiphertextRef);
    this.logger.info('confidential.decrypt.performed', {
      requestId,
      provider: request.provider,
      plaintext,
      requiredAuthorityFields: REQUIRED_AUTHORITY_FIELDS
    });
    return plaintext;
  }
}
