import { ethers, HDNodeWallet, SigningKey } from "ethers";
import { EncryptionKey, EncryptedData } from "../types";

export class Keypair {
  /**
   * Generates a new key pair for encryption
   */
  static async generateKeyPair(): Promise<HDNodeWallet> {
    const wallet = ethers.Wallet.createRandom();
    return wallet;
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
}
