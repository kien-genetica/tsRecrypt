import { ethers } from "ethers";
import { EncryptionKey, EncryptedData } from "../types";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha3_256 } from "js-sha3";
// import { utils } from "ethers"; // for RLP encsoding

export class Encryption {
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

  static hexToBytes(hex: string): Uint8Array {
    return new Uint8Array(
      hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
  }

  static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  static getUncompressedPublicKey(privateKey: Uint8Array): Uint8Array {
    const point = secp256k1.getPublicKey(privateKey, false); // false = uncompressed
    return point;
  }

  static encryptKeygen(priETest: string, priVTest: string) {
    // Generate E, V key-pairs using secp256k1
    const priE = Encryption.hexToBytes(priETest);
    const pubE = Encryption.getUncompressedPublicKey(priE);

    const priV = Encryption.hexToBytes(priVTest);
    const pubV = Encryption.getUncompressedPublicKey(priV);

    // Format public keys to match Go output (uncompressed format)
    console.log("priE:", priETest);
    console.log("pubE:", "04" + Encryption.bytesToHex(pubE));
    console.log("priV:", priVTest);
    console.log("pubV:", "04" + Encryption.bytesToHex(pubV));

    // Concatenate the public keys
    const concatenated = Encryption.concatBytes(pubE, pubV);
    const h = Encryption.hashToCurve(concatenated);

    // Generate S
  }

  static concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    return new Uint8Array([...a, ...b]);
  }

  static sha3Hash(message: Uint8Array): Uint8Array {
    return new Uint8Array(sha3_256.array(message));
  }

  /**
   * Maps a hash value to a point on the curve
   * Returns a BigInt that's within the curve's order
   */
  static hashToCurve(hash: Uint8Array): bigint {
    // Convert hash bytes directly to BigInt (matching Go's SetBytes)
    const hashInt = BigInt("0x" + Buffer.from(hash).toString("hex"));
    // Get curve order N
    const curveN = BigInt(secp256k1.CURVE.n); // 115792089237316195423570985008687907852837564279074904382605163141518161494337n

    // Perform modulo operation (matching Go's Mod operation)
    return hashInt % curveN; //99873723032072448160199860978492267477631206411671014351879442026081161197872n
  }
}

export interface Capsule {
  E: string;
  V: string;
  S: bigint;
}
