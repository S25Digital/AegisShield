import crypto from 'crypto';

const defaultRedactionPatterns = [
  /email|e-mail/i,
  /phone|mobile/i,
  /credit\s?card/i,
  /ssn|social\s?security/i,
  /passport/i,
  /driver\s?license|dl\s?number/i,
  /bank\s?account/i,
  /routing\s?number/i,
  /iban|swift/i,
  /national\s?id|nid/i,
  /date\s?of\s?birth|dob/i,
  /tax\s?id|tin|ein/i,
  /address/i,
  /ip\s?address|ipv4|ipv6/i
];

const defaultMaskingPatterns = [
  /credit\s?card/i,
  /phone|mobile/i,
  /passport/i,
  /driver\s?license|dl\s?number/i
];

type FieldConfig = {
  action: 'redact' | 'mask' | 'encrypt';
  encryptionKey?: Buffer;
};

interface EncryptionConfig {
  algorithm: string;
  key: Buffer;
  iv: Buffer;
}

interface AegisShieldConfig {
  encryptionConfig?: EncryptionConfig;
  fieldConfig?: Record<string, FieldConfig>;
}

export class AegisShield {
  private encryptionConfig?: EncryptionConfig;
  private fieldConfig: Record<string, FieldConfig>;

  constructor(config: AegisShieldConfig = {}) {
    this.encryptionConfig = config.encryptionConfig;
    this.fieldConfig = config.fieldConfig || {};
  }

  public handlePii(data: Record<string, any>): Record<string, any> {
    let sanitizedData = { ...data };

    for (const [key, value] of Object.entries(sanitizedData)) {
      const fieldConfig = this.fieldConfig[key];
      if (fieldConfig) {
        sanitizedData[key] = this.applyFieldConfig(value, fieldConfig);
      } else if (this.isPiiField(key)) {
        if (this.encryptionConfig) {
          sanitizedData[key] = this.encrypt(value);
        } else {
          sanitizedData[key] = this.redactOrMask(value);
        }
      }
    }

    return sanitizedData;
  }

  public reverseEffects(data: Record<string, any>): Record<string, any> {
    let reversedData = { ...data };

    if (this.encryptionConfig) {
      for (const [key, value] of Object.entries(reversedData)) {
        if (this.isEncrypted(value)) {
          reversedData[key] = this.decrypt(value);
        }
      }
    }

    return reversedData;
  }

  private applyFieldConfig(value: any, fieldConfig: FieldConfig): any {
    switch (fieldConfig.action) {
      case 'redact':
        return this.applyRedaction(value);
      case 'mask':
        return this.applyMasking(value);
      case 'encrypt':
        if (fieldConfig.encryptionKey) {
          return this.encrypt(value, fieldConfig.encryptionKey);
        }
        return value;
      default:
        return value;
    }
  }

  private isPiiField(field: string): boolean {
    return defaultRedactionPatterns.some(pattern => pattern.test(field));
  }

  private redactOrMask(value: any): any {
    if (typeof value === 'string') {
      return this.applyRedaction(value) || this.applyMasking(value);
    }
    return value;
  }

  private applyRedaction(value: string): string {
    return value.replace(/./g, '[REDACTED]');
  }

  private applyMasking(value: string): string {
    const pattern = defaultMaskingPatterns.find(pattern => pattern.test(value));
    if (pattern) {
      return value.replace(/.(?=.{4})/g, '*');
    }
    return value;
  }

  private encrypt(value: any, key: Buffer = this.encryptionConfig?.key || Buffer.alloc(0)): string {
    if (typeof value !== 'string' || !this.encryptionConfig) {
      return value;
    }

    const cipher = crypto.createCipheriv(
      this.encryptionConfig.algorithm,
      key,
      this.encryptionConfig.iv
    );
    let encrypted = cipher.update(value, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private decrypt(value: string): string {
    if (!this.encryptionConfig) {
      return value;
    }

    const decipher = crypto.createDecipheriv(
      this.encryptionConfig.algorithm,
      this.encryptionConfig.key,
      this.encryptionConfig.iv
    );
    let decrypted = decipher.update(value, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  private isEncrypted(value: any): boolean {
    return typeof value === 'string' && /^[a-f0-9]{32,}$/i.test(value);
  }
}
