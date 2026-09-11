import { StubConfidentialProvider } from './stub-confidential-provider.js';

export class TeeConfidentialComputeProvider extends StubConfidentialProvider {
  constructor() {
    super('tee', 'trusted-execution-environment');
  }
}
