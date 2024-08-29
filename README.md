# AegisShield

**AegisShield** is a comprehensive TypeScript package for identifying, handling, and protecting Personally Identifiable Information (PII) in data. It provides functionality for detecting common PII fields, applying redaction, masking, or encryption based on user configuration, and reversing these effects where possible.

## Features

- **PII Detection:** Identify common PII fields such as emails, phone numbers, credit card numbers, and more.
- **PII Handling:** 
  - **Redaction:** Replace detected PII with a placeholder (e.g., `[REDACTED]`).
  - **Masking:** Partially obscure PII (e.g., `1234****5678`).
  - **Encryption:** Encrypt PII using a specified algorithm, key, and initialization vector (IV).
- **Reversal of Effects:** Reverse the effects of masking and redaction where applicable, and decrypt encrypted data.

## Installation

To install `AegisShield`, use npm:

```bash
npm install aegis-shield
```

## Usage

### Initialization

Initialize the `AegisShield` class with optional encryption configuration and field-specific configurations.

```typescript
import { AegisShield } from 'aegis-shield';

const shield = new AegisShield({
  encryptionConfig: {
    algorithm: 'aes-256-cbc',
    key: Buffer.from('your-encryption-key-here', 'hex'),
    iv: Buffer.from('your-initialization-vector-here', 'hex')
  },
  fieldConfig: {
    email: { action: 'redact' },
    creditCardNumber: { action: 'mask' },
    ssn: { action: 'encrypt', encryptionKey: Buffer.from('field-specific-key', 'hex') }
  }
});
```

### Handling PII

Handle PII in your data using the `handlePii` method. This method will process the data according to the provided field-specific configurations or default rules.

```typescript
const sensitiveData = {
  email: 'example@example.com',
  phoneNumber: '+1234567890',
  creditCardNumber: '4111111111111111',
  ssn: '123-45-6789'
};

const sanitizedData = shield.handlePii(sensitiveData);
console.log(sanitizedData);
```

### Reversing Effects

Reverse the effects applied by the `handlePii` method (such as decrypting data) using the `reverseEffects` method.

```typescript
const originalData = shield.reverseEffects(sanitizedData);
console.log(originalData);
```

## API Reference

### `AegisShield(config: AegisShieldConfig)`

- **config**: Optional configuration object for encryption and field-specific actions.

### `handlePii(data: Record<string, any>): Record<string, any>`

- **data**: The object containing PII to be handled.
- **Returns**: A new object with PII redacted, masked, or encrypted according to configuration.

### `reverseEffects(data: Record<string, any>): Record<string, any>`

- **data**: The object containing data with effects applied.
- **Returns**: A new object with effects reversed (if applicable).

## Encryption Configuration

The encryption configuration should include:

- **algorithm**: The encryption algorithm (e.g., `'aes-256-cbc'`).
- **key**: The encryption key as a `Buffer`.
- **iv**: The initialization vector (IV) as a `Buffer`.

### Example Encryption Configuration

```typescript
const shield = new AegisShield({
  encryptionConfig: {
    algorithm: 'aes-256-cbc',
    key: Buffer.from('your-encryption-key-here', 'hex'),
    iv: Buffer.from('your-initialization-vector-here', 'hex')
  }
});
```

## License

This package is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
