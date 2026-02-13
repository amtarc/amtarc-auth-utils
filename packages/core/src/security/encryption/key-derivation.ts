/**
 * Key derivation using PBKDF2 and scrypt
 */

import { pbkdf2, scrypt, randomBytes } from 'crypto';
import { promisify } from 'util';

const pbkdf2Async = promisify(pbkdf2);
const scryptAsync = promisify(scrypt) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options?: { N?: number; r?: number; p?: number }
) => Promise<Buffer>;

export interface KeyDerivationOptions {
  /** Salt (generated if not provided) */
  salt?: Buffer | string;
  /** Key length in bytes */
  keyLength?: number;
  /** Algorithm: 'pbkdf2' or 'scrypt' */
  algorithm?: 'pbkdf2' | 'scrypt';
  /** PBKDF2 iterations (default: 100000) */
  iterations?: number;
  /** Scrypt cost parameter (default: 16384) */
  cost?: number;
  /** Scrypt block size (default: 8) */
  blockSize?: number;
  /** Scrypt parallelization (default: 1) */
  parallelization?: number;
}

export interface DerivedKey {
  /** Derived key */
  key: Buffer;
  /** Salt used */
  salt: Buffer;
  /** Algorithm used */
  algorithm: string;
  /** Parameters used */
  params: Record<string, number>;
}

const SALT_LENGTH = 32; // 256 bits
const DEFAULT_KEY_LENGTH = 32; // 256 bits for AES-256

/**
 * Derive encryption key using PBKDF2
 */
export async function deriveKeyPBKDF2(
  password: string | Buffer,
  options: KeyDerivationOptions = {}
): Promise<DerivedKey> {
  const {
    salt = randomBytes(SALT_LENGTH),
    keyLength = DEFAULT_KEY_LENGTH,
    iterations = 100000,
  } = options;

  const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'hex') : salt;
  const passwordBuffer =
    typeof password === 'string' ? Buffer.from(password, 'utf8') : password;

  const key = await pbkdf2Async(
    passwordBuffer,
    saltBuffer,
    iterations,
    keyLength,
    'sha256'
  );

  return {
    key,
    salt: saltBuffer,
    algorithm: 'pbkdf2',
    params: {
      iterations,
      keyLength,
    },
  };
}

/**
 * Derive encryption key using scrypt
 */
export async function deriveKeyScrypt(
  password: string | Buffer,
  options: KeyDerivationOptions = {}
): Promise<DerivedKey> {
  const {
    salt = randomBytes(SALT_LENGTH),
    keyLength = DEFAULT_KEY_LENGTH,
    cost = 16384, // 2^14
    blockSize = 8,
    parallelization = 1,
  } = options;

  const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'hex') : salt;
  const passwordBuffer =
    typeof password === 'string' ? Buffer.from(password, 'utf8') : password;

  const key = await scryptAsync(passwordBuffer, saltBuffer, keyLength, {
    N: cost,
    r: blockSize,
    p: parallelization,
  });

  return {
    key,
    salt: saltBuffer,
    algorithm: 'scrypt',
    params: {
      cost,
      blockSize,
      parallelization,
      keyLength,
    },
  };
}

/**
 * Derive encryption key (uses scrypt by default)
 */
export async function deriveKey(
  password: string | Buffer,
  options: KeyDerivationOptions = {}
): Promise<DerivedKey> {
  const algorithm = options.algorithm || 'scrypt';

  if (algorithm === 'pbkdf2') {
    return deriveKeyPBKDF2(password, options);
  } else if (algorithm === 'scrypt') {
    return deriveKeyScrypt(password, options);
  } else {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}

/**
 * Export derived key as string (for storage)
 */
export function exportDerivedKey(derived: DerivedKey): string {
  const params = Object.entries(derived.params)
    .map(([k, v]) => `${k}=${v}`)
    .join(',');

  return `${derived.algorithm}:${derived.salt.toString('hex')}:${params}`;
}

/**
 * Parse exported key string
 */
export function parseDerivedKey(
  exported: string
): Omit<DerivedKey, 'key'> & KeyDerivationOptions {
  const parts = exported.split(':');

  if (parts.length !== 3) {
    throw new Error('Invalid exported key format');
  }

  const algorithm = parts[0];
  const saltHex = parts[1];
  const paramsStr = parts[2];

  if (!algorithm || !saltHex || !paramsStr) {
    throw new Error('Invalid exported key format: missing components');
  }

  const salt: Buffer = Buffer.from(saltHex, 'hex');

  const params: Record<string, number> = {};
  const options: KeyDerivationOptions = {
    algorithm: algorithm as 'pbkdf2' | 'scrypt',
    salt,
  };

  for (const param of paramsStr.split(',')) {
    const [key, value] = param.split('=');
    if (!key || !value) continue;

    const numValue = parseInt(value, 10);
    params[key] = numValue;

    // Map to options
    if (key === 'iterations') options.iterations = numValue;
    if (key === 'keyLength') options.keyLength = numValue;
    if (key === 'cost') options.cost = numValue;
    if (key === 'blockSize') options.blockSize = numValue;
    if (key === 'parallelization') options.parallelization = numValue;
  }

  const result: Omit<DerivedKey, 'key'> & Partial<KeyDerivationOptions> = {
    salt,
    algorithm: algorithm as 'pbkdf2' | 'scrypt',
    params,
  };

  // Only add optional properties if they exist
  if (options.iterations !== undefined) result.iterations = options.iterations;
  if (options.keyLength !== undefined) result.keyLength = options.keyLength;
  if (options.cost !== undefined) result.cost = options.cost;
  if (options.blockSize !== undefined) result.blockSize = options.blockSize;
  if (options.parallelization !== undefined)
    result.parallelization = options.parallelization;

  return result as Omit<DerivedKey, 'key'> & KeyDerivationOptions;
}
