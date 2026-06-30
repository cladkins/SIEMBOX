import crypto from 'crypto';

/**
 * Encrypted data structure returned by encryption operations
 */
export interface EncryptedData {
  encrypted: string; // Base64-encoded encrypted data
  iv: string; // Base64-encoded initialization vector
  authTag: string; // Base64-encoded authentication tag for GCM
}

/**
 * Credential Encryption Service
 *
 * Provides AES-256-GCM encryption for sensitive credentials used in scanning operations.
 * Uses authenticated encryption to ensure both confidentiality and integrity.
 *
 * Security Features:
 * - AES-256-GCM authenticated encryption
 * - Random IV generation for each encryption operation
 * - Authentication tag verification on decryption
 * - Key derivation from environment variable
 *
 * IMPORTANT: The encryption key must be 32 bytes (256 bits) for AES-256.
 * Set CREDENTIAL_ENCRYPTION_KEY environment variable to a secure random value.
 *
 * Generate a secure key with:
 * node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */
export class CredentialEncryption {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly IV_LENGTH = 12; // 96 bits recommended for GCM
  private static readonly AUTH_TAG_LENGTH = 16; // 128 bits

  /**
   * Get encryption key from environment
   * Validates key length and converts from hex to buffer
   */
  private static getEncryptionKey(): Buffer {
    const keyHex = process.env.CREDENTIAL_ENCRYPTION_KEY;

    if (!keyHex) {
      throw new Error(
        'CREDENTIAL_ENCRYPTION_KEY environment variable not set. ' +
          'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );
    }

    const key = Buffer.from(keyHex, 'hex');

    if (key.length !== 32) {
      throw new Error(
        `CREDENTIAL_ENCRYPTION_KEY must be 32 bytes (256 bits). Current length: ${key.length} bytes. ` +
          'Generate a new key with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
      );
    }

    return key;
  }

  /**
   * Non-throwing configuration check for startup diagnostics. Reports whether
   * CREDENTIAL_ENCRYPTION_KEY is set and valid (64 hex chars = 32 bytes) WITHOUT
   * throwing, so the server can warn loudly at boot instead of only failing when
   * an operator tries to store a credential.
   *
   * Note: Buffer.from(x, 'hex') silently truncates at the first non-hex char, so
   * the raw string is validated as clean hex of the right length here rather than
   * trusting the decoded byte length alone.
   */
  static getKeyStatus(): { configured: boolean; valid: boolean; reason?: string } {
    const keyHex = process.env.CREDENTIAL_ENCRYPTION_KEY;
    if (!keyHex) {
      return { configured: false, valid: false, reason: 'CREDENTIAL_ENCRYPTION_KEY is not set' };
    }
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) {
      return {
        configured: true,
        valid: false,
        reason: `CREDENTIAL_ENCRYPTION_KEY must be 64 hex characters (32 bytes); got ${keyHex.length} character(s)`,
      };
    }
    return { configured: true, valid: true };
  }

  /**
   * Encrypt plaintext using AES-256-GCM
   *
   * @param plaintext - The sensitive data to encrypt
   * @returns Encrypted data with IV and authentication tag
   * @throws Error if encryption fails
   */
  static encrypt(plaintext: string): EncryptedData {
    if (!plaintext) {
      throw new Error('Cannot encrypt empty plaintext');
    }

    // Resolve + validate the key OUTSIDE the try below so its actionable message
    // ("CREDENTIAL_ENCRYPTION_KEY ... not set" / "must be 32 bytes") propagates
    // to callers instead of being flattened into the generic "Failed to encrypt
    // credential". The settings route keys off that text to tell the operator how
    // to fix an unconfigured key.
    const key = this.getEncryptionKey();

    try {
      // Generate random IV for this encryption operation
      const iv = crypto.randomBytes(this.IV_LENGTH);

      // Create cipher
      const cipher = crypto.createCipheriv(this.ALGORITHM, key, iv, {
        authTagLength: this.AUTH_TAG_LENGTH,
      });

      // Encrypt data
      let encrypted = cipher.update(plaintext, 'utf8', 'base64');
      encrypted += cipher.final('base64');

      // Get authentication tag
      const authTag = cipher.getAuthTag();

      return {
        encrypted,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error('Failed to encrypt credential');
    }
  }

  /**
   * Decrypt ciphertext using AES-256-GCM
   *
   * @param encrypted - Base64-encoded encrypted data
   * @param iv - Base64-encoded initialization vector
   * @param authTag - Base64-encoded authentication tag
   * @returns Decrypted plaintext
   * @throws Error if decryption or authentication fails
   */
  static decrypt(encrypted: string, iv: string, authTag: string): string {
    if (!encrypted || !iv || !authTag) {
      throw new Error('Missing required decryption parameters');
    }

    // Resolve + validate the key OUTSIDE the try so a key-configuration error
    // surfaces with its actionable message rather than the generic decrypt error.
    const key = this.getEncryptionKey();

    try {
      // Convert from base64
      const ivBuffer = Buffer.from(iv, 'base64');
      const authTagBuffer = Buffer.from(authTag, 'base64');

      // Validate buffer lengths
      if (ivBuffer.length !== this.IV_LENGTH) {
        throw new Error(`Invalid IV length: ${ivBuffer.length} (expected ${this.IV_LENGTH})`);
      }

      if (authTagBuffer.length !== this.AUTH_TAG_LENGTH) {
        throw new Error(
          `Invalid auth tag length: ${authTagBuffer.length} (expected ${this.AUTH_TAG_LENGTH})`
        );
      }

      // Create decipher
      const decipher = crypto.createDecipheriv(this.ALGORITHM, key, ivBuffer, {
        authTagLength: this.AUTH_TAG_LENGTH,
      });

      // Set authentication tag
      decipher.setAuthTag(authTagBuffer);

      // Decrypt data
      let decrypted = decipher.update(encrypted, 'base64', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch {
      // Don't log the error object here — this runs in the decrypt path for
      // sensitive credentials; a static message avoids any chance of leaking
      // plaintext/secret material into logs. Callers get a descriptive throw.
      console.error('Decryption failed: corrupt data, wrong key, or a tampered auth tag.');
      throw new Error('Failed to decrypt credential. Data may be corrupted or tampered with.');
    }
  }

  /**
   * Re-encrypt data with a new IV
   * Useful for credential rotation without changing the actual credential
   *
   * @param encrypted - Current encrypted data
   * @param iv - Current IV
   * @param authTag - Current authentication tag
   * @returns New encrypted data with new IV and auth tag
   */
  static reEncrypt(encrypted: string, iv: string, authTag: string): EncryptedData {
    try {
      // Decrypt with old parameters
      const plaintext = this.decrypt(encrypted, iv, authTag);

      // Re-encrypt with new IV
      return this.encrypt(plaintext);
    } catch (error) {
      console.error('Re-encryption failed:', error);
      throw new Error('Failed to re-encrypt credential');
    }
  }

  /**
   * Validate that encryption key is properly configured
   * Should be called during application startup
   *
   * @returns true if key is valid, throws error otherwise
   */
  static validateEncryptionKey(): boolean {
    try {
      // Validate key exists and has correct length
      this.getEncryptionKey();

      // Test encryption/decryption
      const testData = 'test-validation';
      const encrypted = this.encrypt(testData);
      const decrypted = this.decrypt(encrypted.encrypted, encrypted.iv, encrypted.authTag);

      if (decrypted !== testData) {
        throw new Error('Encryption validation failed: decrypted data does not match original');
      }

      return true;
    } catch (error) {
      console.error('Encryption key validation failed:', error);
      throw error;
    }
  }

  /**
   * Generate a secure random encryption key
   * Use this to generate CREDENTIAL_ENCRYPTION_KEY value
   *
   * @returns Hex-encoded 256-bit key
   */
  static generateKey(): string {
    return crypto.randomBytes(32).toString('hex');
  }
}
