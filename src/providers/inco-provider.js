import { StubConfidentialProvider } from './stub-confidential-provider.js';

export class IncoConfidentialComputeProvider extends StubConfidentialProvider {
  constructor() {
    super('inco', 'network');
  }
}
