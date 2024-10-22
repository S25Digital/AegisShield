const crypto = require("crypto");
const { AegisShield } = require("../dist");

const shield = new AegisShield({
  encryptionConfig: {
    algorithm: "aes-256-cbc",
    key: Buffer.from(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "hex",
    ), // 32 bytes for AES-256
    iv: Buffer.from("abcdef9876543210abcdef9876543210", "hex"), // 16 bytes IV for AES-CBC
  },
  fieldConfig: {
    email: { action: "redact" },
    creditCardNumber: { action: "mask" },
    "user.phoneNumber": { action: "encrypt" },
    ssn: {
      action: "encrypt",
      encryptionKey: Buffer.from(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "hex",
      ),
    }, // 32 bytes for AES-256
  },
});

const sensitiveData = {
  email: "example@example.com",
  user: {
    phoneNumber: "+1234567890",
  },
  creditCardNumber: "4111111111111111",
  ssn: "123-45-6789",
  passport: "A12345678",
};

// Handle PII in data
const sanitizedData = shield.handlePii(sensitiveData);
console.log("Sanitized Data:", sanitizedData);

// Reverse effects if needed
const originalData = shield.reverseEffects(sanitizedData);
console.log("Original Data:", originalData);
