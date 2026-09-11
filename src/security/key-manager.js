export class ExternalKeyManager {
  async resolveKeyHandle(provider, context) {
    throw new Error(`No external key manager configured for ${provider} (${context?.intentId ?? 'unknown-intent'})`);
  }
}

export class NoopExternalKeyManager extends ExternalKeyManager {
  async resolveKeyHandle(provider, context) {
    return `kms://${provider}/${context.intentId}`;
  }
}
