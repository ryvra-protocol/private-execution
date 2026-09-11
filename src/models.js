import { randomUUID } from 'node:crypto';
import { FailureReasonCode, REQUIRED_AUTHORITY_FIELDS } from './constants.js';

export function nowIso() {
  return new Date().toISOString();
}

function requiredString(value, field) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

export function validateAuthorityLinkage(value) {
  for (const field of REQUIRED_AUTHORITY_FIELDS) {
    requiredString(value?.[field], field);
  }

  return Object.freeze({
    intentId: value.intentId,
    mandateId: value.mandateId,
    policyVersion: value.policyVersion,
    policyHash: value.policyHash,
    riskAssessmentId: value.riskAssessmentId,
    authorizationId: value.authorizationId,
    correlationId: value.correlationId
  });
}

export function createConfidentialIntent(value) {
  return Object.freeze({
    id: value.id ?? randomUUID(),
    ...validateAuthorityLinkage(value),
    action: requiredString(value.action, 'action'),
    createdAt: value.createdAt ?? nowIso(),
    actorRef: requiredString(value.actorRef, 'actorRef'),
    metadata: Object.freeze({ ...(value.metadata ?? {}) })
  });
}

export function createConfidentialExecutionRequest(value) {
  return Object.freeze({
    id: value.id ?? randomUUID(),
    ...validateAuthorityLinkage(value),
    provider: requiredString(value.provider, 'provider'),
    inputRef: requiredString(value.inputRef, 'inputRef'),
    operation: requiredString(value.operation, 'operation'),
    actorRef: requiredString(value.actorRef, 'actorRef'),
    payload: value.payload,
    createdAt: value.createdAt ?? nowIso(),
    metadata: Object.freeze({ ...(value.metadata ?? {}) })
  });
}

export function createConfidentialExecutionResult(value) {
  return Object.freeze({
    id: value.id ?? randomUUID(),
    requestId: requiredString(value.requestId, 'requestId'),
    provider: requiredString(value.provider, 'provider'),
    jobRef: requiredString(value.jobRef, 'jobRef'),
    commitmentHash: requiredString(value.commitmentHash, 'commitmentHash'),
    proofRef: requiredString(value.proofRef, 'proofRef'),
    attestationRef: requiredString(value.attestationRef, 'attestationRef'),
    verified: Boolean(value.verified),
    createdAt: value.createdAt ?? nowIso(),
    metadata: Object.freeze({ ...(value.metadata ?? {}) })
  });
}

export function createVerificationResult(value) {
  return Object.freeze({
    id: value.id ?? randomUUID(),
    requestId: requiredString(value.requestId, 'requestId'),
    provider: requiredString(value.provider, 'provider'),
    decision: value.decision === 'PASS' ? 'PASS' : 'FAIL',
    reasonCode: value.reasonCode ?? (value.decision === 'PASS' ? null : FailureReasonCode.VERIFICATION_FAILED),
    reason: value.reason ?? (value.decision === 'PASS' ? 'Verification passed' : 'Verification failed'),
    commitmentHash: requiredString(value.commitmentHash, 'commitmentHash'),
    proofRef: requiredString(value.proofRef, 'proofRef'),
    attestationRef: requiredString(value.attestationRef, 'attestationRef'),
    policyVersion: requiredString(value.policyVersion, 'policyVersion'),
    policyHash: requiredString(value.policyHash, 'policyHash'),
    verifier: requiredString(value.verifier, 'verifier'),
    actorRef: requiredString(value.actorRef, 'actorRef'),
    createdAt: value.createdAt ?? nowIso()
  });
}

export function createDecryptionAuthorization(value) {
  return Object.freeze({
    id: value.id ?? randomUUID(),
    requestId: requiredString(value.requestId, 'requestId'),
    verificationId: requiredString(value.verificationId, 'verificationId'),
    granted: Boolean(value.granted),
    auditRef: requiredString(value.auditRef, 'auditRef'),
    actorRef: requiredString(value.actorRef, 'actorRef'),
    reasonCode: value.reasonCode ?? null,
    reason: value.reason ?? (value.granted ? 'Decryption authorized' : 'Decryption denied'),
    createdAt: value.createdAt ?? nowIso()
  });
}

export function createProviderCapabilities(value) {
  return Object.freeze({
    provider: requiredString(value.provider, 'provider'),
    encryption: Boolean(value.encryption),
    attestation: Boolean(value.attestation),
    verification: Boolean(value.verification),
    decryptionAuthorization: Boolean(value.decryptionAuthorization),
    externalKeyManagement: Boolean(value.externalKeyManagement),
    deterministicVerification: Boolean(value.deterministicVerification),
    executionModes: Object.freeze([...(value.executionModes ?? [])])
  });
}
