import { StubConfidentialProvider } from './stub-confidential-provider.js';

export class ArciumConfidentialComputeProvider extends StubConfidentialProvider {
  constructor() {
    super('arcium', 'network');
  }
}
