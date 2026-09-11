CREATE TABLE confidential_jobs (
  id TEXT PRIMARY KEY,
  intent_id TEXT NOT NULL,
  mandate_id TEXT NOT NULL,
  authorization_id TEXT NOT NULL,
  correlation_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_job_ref TEXT NOT NULL,
  operation TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_confidential_jobs_intent_id ON confidential_jobs (intent_id);
CREATE INDEX idx_confidential_jobs_mandate_id ON confidential_jobs (mandate_id);
CREATE INDEX idx_confidential_jobs_authorization_id ON confidential_jobs (authorization_id);
CREATE INDEX idx_confidential_jobs_provider ON confidential_jobs (provider);
CREATE INDEX idx_confidential_jobs_created_at ON confidential_jobs (created_at);

CREATE TABLE confidential_inputs (
  id TEXT PRIMARY KEY,
  confidential_job_id TEXT NOT NULL REFERENCES confidential_jobs(id),
  input_ref TEXT NOT NULL,
  ciphertext_ref TEXT NOT NULL,
  input_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_confidential_inputs_created_at ON confidential_inputs (created_at);

CREATE TABLE confidential_results (
  id TEXT PRIMARY KEY,
  confidential_job_id TEXT NOT NULL REFERENCES confidential_jobs(id),
  commitment_hash TEXT NOT NULL,
  result_ciphertext_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_confidential_results_created_at ON confidential_results (created_at);

CREATE TABLE provider_attestations (
  id TEXT PRIMARY KEY,
  confidential_job_id TEXT NOT NULL REFERENCES confidential_jobs(id),
  provider TEXT NOT NULL,
  proof_ref TEXT NOT NULL,
  attestation_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_provider_attestations_provider ON provider_attestations (provider);
CREATE INDEX idx_provider_attestations_created_at ON provider_attestations (created_at);

CREATE TABLE verification_records (
  id TEXT PRIMARY KEY,
  confidential_job_id TEXT NOT NULL REFERENCES confidential_jobs(id),
  provider TEXT NOT NULL,
  commitment_hash TEXT NOT NULL,
  proof_ref TEXT NOT NULL,
  attestation_ref TEXT NOT NULL,
  verifier_decision TEXT NOT NULL,
  reason_code TEXT,
  reason TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  verifier_actor_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (confidential_job_id)
);

CREATE INDEX idx_verification_records_provider ON verification_records (provider);
CREATE INDEX idx_verification_records_created_at ON verification_records (created_at);

CREATE TABLE decrypt_authorizations (
  id TEXT PRIMARY KEY,
  confidential_job_id TEXT NOT NULL REFERENCES confidential_jobs(id),
  authorization_id TEXT NOT NULL,
  verification_record_id TEXT NOT NULL REFERENCES verification_records(id),
  decision TEXT NOT NULL,
  reason_code TEXT,
  reason TEXT NOT NULL,
  audit_ref TEXT NOT NULL,
  actor_ref TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_decrypt_authorizations_authorization_id ON decrypt_authorizations (authorization_id);
CREATE INDEX idx_decrypt_authorizations_created_at ON decrypt_authorizations (created_at);
