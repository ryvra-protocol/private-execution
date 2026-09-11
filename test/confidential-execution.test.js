import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ArciumConfidentialComputeProvider,
  ConfidentialExecutionService,
  FailureReasonCode,
  InMemoryConfidentialStore,
  IncoConfidentialComputeProvider,
  MemoryLogger,
  TeeConfidentialComputeProvider,
  ZkConfidentialComputeProvider,
  assertProviderContract
} from '../src/index.js';

function buildProviders() {
  return {
    inco: new IncoConfidentialComputeProvider(),
    arcium: new ArciumConfidentialComputeProvider(),
    zk: new ZkConfidentialComputeProvider(),
    tee: new TeeConfidentialComputeProvider()
  };
}

function buildRequest(provider = 'inco', overrides = {}) {
  return {
    intentId: 'intent-1',
    mandateId: 'mandate-1',
    policyVersion: '2026-09-11',
    policyHash: 'policy-hash-1',
    riskAssessmentId: 'risk-1',
    authorizationId: 'auth-1',
    correlationId: 'corr-1',
    provider,
    inputRef: 'vault://input/1',
    operation: 'net-settle',
    actorRef: 'actor:ops',
    payload: { account: '1234', amount: 42, plaintextSecret: 'do-not-log' },
    ...overrides
  };
}

test('all providers satisfy the provider contract and expose capabilities', () => {
  for (const provider of Object.values(buildProviders())) {
    assert.equal(assertProviderContract(provider), true);
    const capabilities = provider.getCapabilities();
    assert.equal(capabilities.provider, provider.name);
    assert.equal(capabilities.verification, true);
    assert.equal(capabilities.decryptionAuthorization, true);
    assert.ok(capabilities.executionModes.length > 0);
  }
});

test('happy path enforces encrypt compute verify authorize decrypt lifecycle', async () => {
  const logger = new MemoryLogger();
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore(), logger });

  await service.submitConfidentialIntent({ ...buildRequest(), action: 'settle-payment' });
  const result = await service.executeConfidentialCompute(buildRequest());
  const verification = await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
    actorRef: 'actor:verifier'
  });
  const authorization = await service.requestDecryption({ requestId: result.requestId, actorRef: 'actor:approver' });
  const plaintext = await service.performDecryption({ requestId: result.requestId });

  assert.equal(verification.decision, 'PASS');
  assert.equal(authorization.granted, true);
  assert.equal(plaintext, result.commitmentHash);
});

test('verification failure blocks decryption', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });
  const result = await service.executeConfidentialCompute(buildRequest());
  const verification = await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: 'wrong-version', policyHash: 'wrong-hash' },
    actorRef: 'actor:verifier'
  });
  const authorization = await service.requestDecryption({ requestId: result.requestId, actorRef: 'actor:approver' });

  assert.equal(verification.decision, 'FAIL');
  assert.equal(verification.reasonCode, FailureReasonCode.POLICY_MISMATCH);
  assert.equal(authorization.granted, false);
  await assert.rejects(() => service.performDecryption({ requestId: result.requestId }), (error) => error.code === FailureReasonCode.DECRYPT_NOT_AUTHORIZED);
});

test('missing policy fails closed during verification', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });
  const result = await service.executeConfidentialCompute(buildRequest());

  await assert.rejects(
    () => service.verifyConfidentialResult({ requestId: result.requestId, actorRef: 'actor:verifier' }),
    (error) => error.code === FailureReasonCode.INVALID_POLICY
  );
});

test('unknown request fails closed during verification', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });

  await assert.rejects(
    () => service.verifyConfidentialResult({
      requestId: 'missing-request',
      policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
      actorRef: 'actor:verifier'
    }),
    (error) => error.code === FailureReasonCode.UNKNOWN_REQUEST
  );
});

test('missing linkage fails closed', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });

  await assert.rejects(
    () => service.executeConfidentialCompute(buildRequest('inco', { mandateId: '' })),
    /mandateId is required/
  );
});

test('logs redact plaintext and sensitive values', async () => {
  const logger = new MemoryLogger();
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore(), logger });

  const result = await service.executeConfidentialCompute(buildRequest());
  await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
    actorRef: 'actor:verifier'
  });
  await service.requestDecryption({ requestId: result.requestId, actorRef: 'actor:approver' });
  await service.performDecryption({ requestId: result.requestId });

  const serialized = JSON.stringify(logger.entries);
  assert.equal(serialized.includes('do-not-log'), false);
  assert.match(serialized, /\[REDACTED\]/);
});

test('same logical request can route through different providers with normalized outputs', async () => {
  const providers = ['inco', 'arcium', 'zk', 'tee'];
  const outputs = [];

  for (const provider of providers) {
    const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });
    const result = await service.executeConfidentialCompute(buildRequest(provider));
    const verification = await service.verifyConfidentialResult({
      requestId: result.requestId,
      policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
      actorRef: 'actor:verifier'
    });

    outputs.push({ provider, result, verification });
  }

  for (const entry of outputs) {
    assert.equal(entry.result.provider, entry.provider);
    assert.equal(typeof entry.result.commitmentHash, 'string');
    assert.equal(entry.verification.decision, 'PASS');
    assert.equal(entry.verification.provider, entry.provider);
  }
});

test('provenance records are persisted and queryable by intent and correlation identifiers', async () => {
  const store = new InMemoryConfidentialStore();
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store });
  const result = await service.executeConfidentialCompute(buildRequest('tee', { intentId: 'intent-xyz', correlationId: 'corr-xyz' }));
  await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
    actorRef: 'actor:verifier'
  });

  const byIntent = store.queryProvenance({ intentId: 'intent-xyz' });
  const byCorrelation = store.queryProvenance({ correlationId: 'corr-xyz' });

  assert.equal(byIntent.length, 1);
  assert.equal(byIntent[0].provider, 'tee');
  assert.equal(byCorrelation[0].commitmentHash, result.commitmentHash);
});

test('verification outcomes are immutable', async () => {
  const store = new InMemoryConfidentialStore();
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store });
  const result = await service.executeConfidentialCompute(buildRequest('zk', { correlationId: 'corr-immutable' }));

  await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
    actorRef: 'actor:verifier'
  });

  await assert.rejects(
    () => service.verifyConfidentialResult({
      requestId: result.requestId,
      policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
      actorRef: 'actor:verifier-2'
    }),
    /immutable/
  );
});

test('decryption requires verification record and authorization', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });
  const result = await service.executeConfidentialCompute(buildRequest('arcium', { correlationId: 'corr-guard' }));

  await assert.rejects(
    () => service.performDecryption({ requestId: result.requestId }),
    (error) => error.code === FailureReasonCode.DECRYPT_NOT_AUTHORIZED
  );
});

test('decryption requires authorization even after verification succeeds', async () => {
  const service = new ConfidentialExecutionService({ providers: buildProviders(), store: new InMemoryConfidentialStore() });
  const result = await service.executeConfidentialCompute(buildRequest('tee', { correlationId: 'corr-auth-gap' }));

  await service.verifyConfidentialResult({
    requestId: result.requestId,
    policy: { policyVersion: '2026-09-11', policyHash: 'policy-hash-1' },
    actorRef: 'actor:verifier'
  });

  await assert.rejects(
    () => service.performDecryption({ requestId: result.requestId }),
    (error) => error.code === FailureReasonCode.DECRYPT_NOT_AUTHORIZED
  );
});
