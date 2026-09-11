import { nowIso } from '../models.js';

export class InMemoryConfidentialStore {
  constructor() {
    this.intents = new Map();
    this.requests = new Map();
    this.jobs = new Map();
    this.inputs = new Map();
    this.results = new Map();
    this.verifications = new Map();
    this.decryptionAuthorizations = new Map();
    this.providerAttestations = new Map();
  }

  saveIntent(intent) {
    this.intents.set(intent.id, intent);
    return intent;
  }

  saveRequest(request) {
    this.requests.set(request.id, request);
    return request;
  }

  saveInput(inputRecord) {
    this.inputs.set(inputRecord.id, Object.freeze({ createdAt: nowIso(), ...inputRecord }));
    return this.inputs.get(inputRecord.id);
  }

  saveJob(jobRecord) {
    this.jobs.set(jobRecord.id, Object.freeze({ createdAt: nowIso(), ...jobRecord }));
    return this.jobs.get(jobRecord.id);
  }

  saveResult(result) {
    this.results.set(result.confidentialJobId, result);
    return result;
  }

  saveVerification(record) {
    if (this.verifications.has(record.confidentialJobId)) {
      throw new Error('Verification records are immutable');
    }

    this.verifications.set(record.confidentialJobId, record);
    return record;
  }

  saveDecryptionAuthorization(record) {
    if (this.decryptionAuthorizations.has(record.confidentialJobId)) {
      throw new Error('Decryption authorizations are immutable');
    }

    this.decryptionAuthorizations.set(record.confidentialJobId, record);
    return record;
  }

  saveProviderAttestation(record) {
    this.providerAttestations.set(record.confidentialJobId, Object.freeze({ createdAt: nowIso(), ...record }));
    return this.providerAttestations.get(record.confidentialJobId);
  }

  getIntent(intentId) {
    return this.intents.get(intentId);
  }

  getRequest(requestId) {
    return this.requests.get(requestId);
  }

  getResult(requestId) {
    return this.results.get(requestId);
  }

  getVerification(requestId) {
    return this.verifications.get(requestId);
  }

  getDecryptionAuthorization(requestId) {
    return this.decryptionAuthorizations.get(requestId);
  }

  queryProvenance({ intentId, correlationId }) {
    return Array.from(this.requests.values())
      .filter((request) => (!intentId || request.intentId === intentId) && (!correlationId || request.correlationId === correlationId))
      .map((request) => {
        const result = this.getResult(request.id);
        const verification = this.getVerification(request.id);
        return Object.freeze({
          provider: request.provider,
          requestId: request.id,
          intentId: request.intentId,
          correlationId: request.correlationId,
          jobRef: result?.jobRef ?? null,
          commitmentHash: result?.commitmentHash ?? null,
          proofRef: result?.proofRef ?? null,
          verifierDecision: verification?.decision ?? null,
          verificationCreatedAt: verification?.createdAt ?? null,
          actorRef: verification?.actorRef ?? request.actorRef
        });
      });
  }
}
