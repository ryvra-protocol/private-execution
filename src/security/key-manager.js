import { createHash } from 'node:crypto';

export class ExternalKeyManager {
  async resolveKeyHandle(provider, context) {
    throw new Error(`No external key manager configured for ${provider} (${context?.intentId ?? 'unknown-intent'})`);
  }
}

export class NoopExternalKeyManager extends ExternalKeyManager {
  async resolveKeyHandle(provider, context) {
    const scopeHash = createHash('sha256').update(JSON.stringify(context)).digest('hex');
    return `kms://${provider}/${context.intentId}/${scopeHash}`;
  }
}
