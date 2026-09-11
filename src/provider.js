export class ConfidentialComputeProvider {
  constructor(name, capabilities) {
    this.name = name;
    this.capabilities = capabilities;
  }

  getCapabilities() {
    return this.capabilities;
  }

  async encrypt() {
    throw new Error('encrypt must be implemented');
  }

  async compute() {
    throw new Error('compute must be implemented');
  }

  async verify() {
    throw new Error('verify must be implemented');
  }

  async authorizeDecrypt() {
    throw new Error('authorizeDecrypt must be implemented');
  }

  async decrypt() {
    throw new Error('decrypt must be implemented');
  }
}

export function assertProviderContract(provider) {
  for (const method of ['encrypt', 'compute', 'verify', 'authorizeDecrypt', 'decrypt', 'getCapabilities']) {
    if (typeof provider?.[method] !== 'function') {
      throw new Error(`Provider missing method: ${method}`);
    }
  }

  return true;
}
