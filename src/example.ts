import { AegisShield } from "./shield";

// Example usage
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

const sensitiveData = {
  email: 'example@example.com',
  phoneNumber: '+1234567890',
  creditCardNumber: '4111111111111111',
  ssn: '123-45-6789'
};

const sanitizedData = shield.handlePii(sensitiveData);
console.log(sanitizedData);

const originalData = shield.reverseEffects(sanitizedData);
console.log(originalData);