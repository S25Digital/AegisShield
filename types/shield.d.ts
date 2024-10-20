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
export declare class AegisShield {
    private encryptionConfig?;
    private fieldConfig;
    constructor(config?: AegisShieldConfig);
    handlePii(data: Record<string, any>): Record<string, any>;
    reverseEffects(data: Record<string, any>): Record<string, any>;
    private applyFieldConfig;
    private isPiiField;
    private redactOrMask;
    private applyMasking;
    private encrypt;
    private decrypt;
    private isEncrypted;
}
export {};
