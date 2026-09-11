import { StubConfidentialProvider } from './stub-confidential-provider.js';

export class ZkConfidentialComputeProvider extends StubConfidentialProvider {
  constructor() {
    super('zk', 'zero-knowledge');
  }
}
