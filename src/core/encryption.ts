import { ethers } from "ethers";
import { EncryptionKey, EncryptedData } from "../types";

export class Encryption {
  /**
   * Generates a new key pair for encryption
   */
  static async generateKeyPair() {
    const wallet = ethers.Wallet.createRandom();
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
