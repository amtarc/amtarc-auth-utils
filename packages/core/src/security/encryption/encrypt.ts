/**
 * Encryption utilities using Node.js crypto
 * AES-256-GCM encryption with key derivation
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export interface EncryptionOptions {
  /** Encryption key (32 bytes for AES-256) */
  key: Buffer;
  /** Additional authenticated data (optional) */
  aad?: Buffer | string;
}

export interface EncryptedData {
  /** Encrypted ciphertext (base64) */
  ciphertext: string;
  /** Initialization vector (base64) */
  iv: string;
  /** Authentication tag (base64) */
  authTag: string;
  /** Algorithm used */
  algorithm: string;
}

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM

/**
 * Encrypt data using AES-256-GCM
 */
export function encrypt(
  plaintext: string | Buffer,
  options: EncryptionOptions
): EncryptedData {
  const { key, aad } = options;

  // Validate key size
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes for AES-256');
  }

  // Generate random IV
  const iv = randomBytes(IV_LENGTH);

  // Create cipher
  const cipher = createCipheriv(ALGORITHM, key, iv);

  // Set AAD if provided
  if (aad) {
    const aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf8') : aad;
    cipher.setAAD(aadBuffer);
  }

  // Encrypt
  const plaintextBuffer =
    typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext;

  const encrypted = Buffer.concat([
    cipher.update(plaintextBuffer),
    cipher.final(),
  ]);

  // Get auth tag
  const authTag = cipher.getAuthTag();

  return {
    ciphertext: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    algorithm: ALGORITHM,
  };
}

/**
 * Decrypt data using AES-256-GCM
 */
export function decrypt(
  encrypted: EncryptedData,
  options: EncryptionOptions
): Buffer {
  const { key, aad } = options;
  const { ciphertext, iv, authTag, algorithm } = encrypted;

  // Validate key size
  if (key.length !== 32) {
    throw new Error('Encryption key must be 32 bytes for AES-256');
  }

  // Validate algorithm
  if (algorithm !== ALGORITHM) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // Parse encrypted data
  const ivBuffer = Buffer.from(iv, 'base64');
  const authTagBuffer = Buffer.from(authTag, 'base64');
  const ciphertextBuffer = Buffer.from(ciphertext, 'base64');

  // Create decipher
  const decipher = createDecipheriv(ALGORITHM, key, ivBuffer);
  decipher.setAuthTag(authTagBuffer);

  // Set AAD if provided
  if (aad) {
    const aadBuffer = typeof aad === 'string' ? Buffer.from(aad, 'utf8') : aad;
    decipher.setAAD(aadBuffer);
  }

  // Decrypt
  try {
    return Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);
  } catch (error) {
    throw new Error(
      'Decryption failed: authentication tag verification failed'
    );
  }
}

/**
 * Encrypt and return as single string (formats: iv.authTag.ciphertext)
 */
export function encryptToString(
  plaintext: string | Buffer,
  options: EncryptionOptions
): string {
  const encrypted = encrypt(plaintext, options);
  return `${encrypted.iv}.${encrypted.authTag}.${encrypted.ciphertext}`;
}

/**
 * Decrypt from string format
 */
export function decryptFromString(
  encryptedString: string,
  options: EncryptionOptions
): Buffer {
  const parts = encryptedString.split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid encrypted string format');
  }

  const iv = parts[0];
  const authTag = parts[1];
  const ciphertext = parts[2];

  if (!iv || !authTag || !ciphertext) {
    throw new Error('Invalid encrypted string format: missing components');
  }

  return decrypt(
    {
      iv,
      authTag,
      ciphertext,
      algorithm: ALGORITHM,
    },
    options
  );
}
