import {
  EncryptionKey,
  ReEncryptionKey,
  EncryptedData,
  ReEncryptedData,
} from "../types";

export class ReEncryption {
  /**
   * Generates re-encryption key from delegator to delegatee
   */
  static async generateReEncryptionKey(
    delegatorPrivateKey: Uint8Array,
    delegateePublicKey: Uint8Array
  ): Promise<ReEncryptionKey> {
    // TODO: Implement re-encryption key generation
    throw new Error("Not implemented");
  }

  /**
   * Re-encrypts data for delegatee
   */
  static async reEncrypt(
    encryptedData: EncryptedData,
    reEncryptionKey: ReEncryptionKey
  ): Promise<ReEncryptedData> {
    // TODO: Implement re-encryption
    throw new Error("Not implemented");
  }
}
