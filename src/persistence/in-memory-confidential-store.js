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
    if (this.intents.has(intent.id)) {
      throw new Error('Intent records are immutable');
    }
    this.intents.set(intent.id, intent);
    return intent;
  }

  saveRequest(request) {
    if (this.requests.has(request.id)) {
      throw new Error('Request records are immutable');
    }
    this.requests.set(request.id, request);
    return request;
  }

  saveExecution(records) {
    const { request, job, input, attestation, result } = records;
    if (this.requests.has(request.id) || this.jobs.has(job.id) || this.results.has(result.confidentialJobId)) {
      throw new Error('Execution records are immutable');
    }

    const nextRequests = new Map(this.requests);
    const nextJobs = new Map(this.jobs);
    const nextInputs = new Map(this.inputs);
    const nextAttestations = new Map(this.providerAttestations);
    const nextResults = new Map(this.results);

    nextRequests.set(request.id, request);
    nextJobs.set(job.id, Object.freeze({ createdAt: nowIso(), ...job }));
    nextInputs.set(input.id, Object.freeze({ createdAt: nowIso(), ...input }));
    nextAttestations.set(attestation.confidentialJobId, Object.freeze({ createdAt: nowIso(), ...attestation }));
    nextResults.set(result.confidentialJobId, result);

    this.requests = nextRequests;
    this.jobs = nextJobs;
    this.inputs = nextInputs;
    this.providerAttestations = nextAttestations;
    this.results = nextResults;

    return result;
  }

  saveInput(inputRecord) {
    if (this.inputs.has(inputRecord.id)) {
      throw new Error('Input records are immutable');
    }
    this.inputs.set(inputRecord.id, Object.freeze({ createdAt: nowIso(), ...inputRecord }));
    return this.inputs.get(inputRecord.id);
  }

  saveJob(jobRecord) {
    if (this.jobs.has(jobRecord.id)) {
      throw new Error('Job records are immutable');
    }
    this.jobs.set(jobRecord.id, Object.freeze({ createdAt: nowIso(), ...jobRecord }));
    return this.jobs.get(jobRecord.id);
  }

  saveResult(result) {
    if (this.results.has(result.confidentialJobId)) {
      throw new Error('Result records are immutable');
    }
    this.results.set(result.confidentialJobId, result);
    return result;
  }

  saveVerification(record) {
    if (this.verifications.has(record.confidentialJobId)) {
      throw new Error('Verification records are immutable');
    }

    const persisted = Object.freeze({ createdAt: record.createdAt ?? nowIso(), ...record });
    this.verifications.set(record.confidentialJobId, persisted);
    return persisted;
  }

  saveDecryptionAuthorization(record) {
    if (this.decryptionAuthorizations.has(record.confidentialJobId)) {
      throw new Error('Decryption authorizations are immutable');
    }

    const persisted = Object.freeze({ createdAt: record.createdAt ?? nowIso(), ...record });
    this.decryptionAuthorizations.set(record.confidentialJobId, persisted);
    return persisted;
  }

  saveProviderAttestation(record) {
    if (this.providerAttestations.has(record.confidentialJobId)) {
      throw new Error('Provider attestations are immutable');
    }
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
