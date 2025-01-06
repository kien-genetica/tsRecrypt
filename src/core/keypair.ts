import { ethers, SigningKey } from "ethers";
import { EncryptionKey, EncryptedData } from "../types";

export class Keypair {
  /**
   * Generates a new key pair for encryption
   */
  static async generateKeyPair() {
    const wallet = ethers.Wallet.createRandom();
  }

  static async fromPrivateKey(privateKey: string): Promise<EncryptionKey> {
    // Add 0x prefix if not present
    const formattedKey = privateKey.startsWith("0x")
      ? privateKey
      : `0x${privateKey}`;

    // Create SigningKey directly to access the public key
    const signingKey = new SigningKey(formattedKey);

    // Get the uncompressed public key
    const publicKeyBytes = signingKey.publicKey;
    const publicKey = publicKeyBytes.slice(2); // Remove '0x' prefix

    return {
      privateKey: formattedKey,
      publicKey,
    };
  }

  /**
   * Encrypts data using recipient's public key
   */
  static async encrypt(
    data: Uint8Array,
    recipientPublicKey: Uint8Array
  ): Promise<EncryptedData> {
    // TODO: Implement encryption
    throw new Error("Not implemented");
  }

  /**
   * Decrypts data using recipient's private key
   */
  static async decrypt(
    encryptedData: EncryptedData,
    privateKey: Uint8Array
  ): Promise<Uint8Array> {
    // TODO: Implement decryption
    throw new Error("Not implemented");
  }
}
