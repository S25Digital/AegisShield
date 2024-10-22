import crypto from "crypto";

// Utility functions for redaction and masking
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
  /ip\s?address|ipv4|ipv6/i,
];

type FieldConfig = {
  action: "redact" | "mask" | "encrypt";
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
    return this.processObject(data);
  }

  public reverseEffects(data: Record<string, any>): Record<string, any> {
    return this.processObject(data, true);
  }

  private processObject(data: any, reverse = false, parentKey = ""): any {
    if (typeof data !== "object" || data === null || Buffer.isBuffer(data)) {
      return data;
    }

    const result: Record<string, any> = Array.isArray(data)
      ? [...data]
      : { ...data };

    for (const [key, value] of Object.entries(result)) {
      const fullKeyPath = parentKey ? `${parentKey}.${key}` : key;
      const fieldConfig = this.getFieldConfig(fullKeyPath);

      if (
        typeof value === "object" &&
        value !== null &&
        !Buffer.isBuffer(value)
      ) {
        result[key] = this.processObject(value, reverse, fullKeyPath);
      } else if (fieldConfig) {
        result[key] = reverse
          ? this.reverseField(value, fieldConfig)
          : this.applyFieldConfig(value, fieldConfig);
      } else if (this.isPiiField(key) && !reverse) {
        result[key] = this.redactOrMask(value);
      }
    }

    return result;
  }

  private getFieldConfig(keyPath: string): FieldConfig | undefined {
    return this.fieldConfig[keyPath];
  }

  private applyFieldConfig(value: any, fieldConfig: FieldConfig): any {
    switch (fieldConfig.action) {
      case "redact":
        return "[REDACTED]";
      case "mask":
        return this.applyMasking(value);
      case "encrypt":
        if (fieldConfig.encryptionKey) {
          return this.encrypt(
            value,
            fieldConfig.encryptionKey,
            this.encryptionConfig?.iv || Buffer.alloc(16),
          );
        }
        return value;
      default:
        return value;
    }
  }

  private reverseField(value: any, fieldConfig: FieldConfig): any {
    if (fieldConfig.action === "encrypt" && fieldConfig.encryptionKey) {
      return this.decrypt(
        value,
        fieldConfig.encryptionKey,
        this.encryptionConfig?.iv || Buffer.alloc(16),
      );
    }
    return value;
  }

  private isPiiField(field: string): boolean {
    return defaultRedactionPatterns.some((pattern) => pattern.test(field));
  }

  private redactOrMask(value: any): any {
    if (typeof value === "string") {
      return "[REDACTED]";
    }
    return value;
  }

  private applyMasking(value: string): string {
    if (typeof value === "string" && value.length > 4) {
      return value.slice(0, -4).replace(/./g, "*") + value.slice(-4);
    }
    return value;
  }

  private encrypt(value: any, key: Buffer, iv: Buffer): string {
    if (typeof value !== "string") {
      return value;
    }

    try {
      const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
      let encrypted = cipher.update(value, "utf8", "hex");
      encrypted += cipher.final("hex");
      return encrypted;
    } catch (error) {
      console.error("Encryption error:", error.message);
      throw error;
    }
  }

  private decrypt(value: string, key: Buffer, iv: Buffer): string {
    try {
      const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
      let decrypted = decipher.update(value, "hex", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch (error) {
      console.error("Decryption error:", error.message);
      throw error;
    }
  }

  private isEncrypted(value: any): boolean {
    return typeof value === "string" && /^[a-f0-9]{32,}$/i.test(value);
  }
}
