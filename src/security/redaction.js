const SENSITIVE_KEYS = ['payload', 'plaintext', 'secret', 'key', 'token', 'ssn', 'input'];

export function redactSensitive(value) {
  if (Array.isArray(value)) {
    return value.map(redactSensitive);
  }

  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => {
        const sensitive = SENSITIVE_KEYS.some((needle) => key.toLowerCase().includes(needle));
        return [key, sensitive ? '[REDACTED]' : redactSensitive(entry)];
      })
    );
  }

  return value;
}

export class MemoryLogger {
  constructor() {
    this.entries = [];
  }

  info(message, context = {}) {
    this.entries.push({ level: 'info', message, context: redactSensitive(context) });
  }

  error(message, context = {}) {
    this.entries.push({ level: 'error', message, context: redactSensitive(context) });
  }
}
