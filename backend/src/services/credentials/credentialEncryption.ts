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
   * Encrypt plaintext using AES-256-GCM
   *
   * @param plaintext - The sensitive data to encrypt
   * @returns Encrypted data with IV and authentication tag
   * @throws Error if encryption fails
   */
  static encrypt(plaintext: string): EncryptedData {
    try {
      if (!plaintext) {
        throw new Error('Cannot encrypt empty plaintext');
      }

      const key = this.getEncryptionKey();

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
    try {
      if (!encrypted || !iv || !authTag) {
        throw new Error('Missing required decryption parameters');
      }

      const key = this.getEncryptionKey();

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
    } catch (error) {
      console.error('Decryption failed:', error);
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
      const key = this.getEncryptionKey();

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
