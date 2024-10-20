// test/AegisShield.test.ts
import { expect } from 'chai';
import { AegisShield } from '../src/shield';
import crypto from 'crypto';

describe('AegisShield', () => {
  const encryptionConfig = {
    algorithm: 'aes-256-cbc',
    key: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', 'hex'), // 32 bytes for AES-256
    iv: Buffer.from('abcdef9876543210abcdef9876543210', 'hex') // 16 bytes IV for AES-CBC
  };

  const fieldConfig: any = {
    email: { action: 'redact' },
    creditCardNumber: { action: 'mask' },
    ssn: { action: 'encrypt', encryptionKey: encryptionConfig.key } // Use the same key as encryptionConfig
  };

  const shield = new AegisShield({ encryptionConfig, fieldConfig });

  it('should redact email fields', () => {
    const data = { email: 'example@example.com' };
    const result = shield.handlePii(data);
    expect(result.email).to.equal('[REDACTED]');
  });

  it('should mask credit card number', () => {
    const data = { creditCardNumber: '4111111111111111' };
    const result = shield.handlePii(data);
    expect(result.creditCardNumber).to.equal('************1111');
  });

  it('should decrypt encrypted ssn field', () => {
    const data = { ssn: '123-45-6789' };
    const encryptedData = shield.handlePii(data);
    const decryptedData = shield.reverseEffects(encryptedData);
    expect(decryptedData.ssn).to.equal(data.ssn);
  });

  it('should handle non-PII fields without modification', () => {
    const data = { nonPiiField: 'someValue' };
    const result = shield.handlePii(data);
    expect(result.nonPiiField).to.equal('someValue');
  });

  it('should throw an error for invalid decryption key', () => {
    const invalidShield = new AegisShield({
      encryptionConfig: {
        algorithm: 'aes-256-cbc',
        key: Buffer.from('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd', 'hex'), // Incorrect length
        iv: encryptionConfig.iv
      },
      fieldConfig
    });

    const data = { ssn: '123-45-6789' };
    const encryptedData = invalidShield.handlePii(data);
    expect(() => invalidShield.reverseEffects(encryptedData)).to.throw();
  });
});
