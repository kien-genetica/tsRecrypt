import { ethers } from "ethers";
import { EncryptionKey, EncryptedData } from "../types";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha3_256 } from "js-sha3";
import { webcrypto } from "crypto";
const crypto = webcrypto;

export class Encryption {
  /**
   * Encrypts data using recipient's public key
   */
  static async encrypt(
    data: string,
    recipientPublicKey: Uint8Array,
    privETest: string,
    privVTest: string
  ): Promise<Uint8Array> {
    const encryptKeyGen = Encryption.encryptKeygen(
      recipientPublicKey,
      privETest,
      privVTest
    );

    const keyBytes = Encryption.hexToBytes(encryptKeyGen.aesKey);
    const key = encryptKeyGen.aesKey.slice(0, 32); // Take first 32 chars of hex string
    const nonce = keyBytes.slice(0, 12); // Take first 12 bytes as nonce

    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(data);

    // Import key properly for AES-GCM
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(key),
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      cryptoKey,
      dataBytes
    );

    const ciphertextBytes = new Uint8Array(ciphertext);
    return ciphertextBytes;
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

  // TODO: generate privE, privV inside the function
  static encryptKeygen(
    pubkey: Uint8Array,
    priETest: string,
    priVTest: string
  ): EncryptKeyGen {
    // Generate E, V key-pairs using secp256k1
    const priE = Encryption.hexToBytes(priETest);
    const pubE = Encryption.getUncompressedPublicKey(priE);

    const priV = Encryption.hexToBytes(priVTest);
    const pubV = Encryption.getUncompressedPublicKey(priV);

    // Format public keys to match Go output (uncompressed format)
    // console.log("priE:", priETest);
    // console.log("pubE:", "04" + Encryption.bytesToHex(pubE));
    // console.log("priV:", priVTest);
    // console.log("pubV:", "04" + Encryption.bytesToHex(pubV));

    // Concatenate the public keys
    const concatenated = Encryption.concatBytes(pubE, pubV);
    const h = Encryption.hashToCurve(concatenated);

    // Generate S
    // get s = v + e * H2(E || V)
    const priEBig = BigInt("0x" + priETest);
    const priVBig = BigInt("0x" + priVTest);
    const mul = bigIntMul(priEBig, h);
    const s = bigIntAdd(priVBig, mul);

    // get (pk_A)^{e+v}
    const sum = bigIntAdd(priEBig, priVBig); // sum = e + v
    const point = Encryption.pointScalarMul(pubkey, sum);

    // Generate aes key
    const aesKey = sha3Hash(point);

    return {
      Capsule: {
        E: Encryption.bytesToHex(point),
        V: Encryption.bytesToHex(priV),
        S: s,
      },
      aesKey: Encryption.bytesToHex(aesKey),
    };
  }

  static concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    return new Uint8Array([...a, ...b]);
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

  static pointScalarMul(point: Uint8Array, scalar: bigint): Uint8Array {
    // Convert the uncompressed public key point to ProjectivePoint
    const P = secp256k1.ProjectivePoint.fromHex(
      Buffer.from(point).toString("hex")
    );

    // Perform scalar multiplication
    const result = P.multiply(scalar);

    // Convert back to uncompressed format
    return result.toRawBytes(false);
  }
}

export interface EncryptKeyGen {
  Capsule: Capsule;
  aesKey: string;
}
export interface Capsule {
  E: string;
  V: string;
  S: bigint;
}

function bigIntMul(a: bigint, b: bigint): bigint {
  const curveN = BigInt(secp256k1.CURVE.n);
  return (a * b) % curveN;
}

function bigIntAdd(a: bigint, b: bigint): bigint {
  const curveN = BigInt(secp256k1.CURVE.n);
  return (a + b) % curveN;
}

function sha3Hash(message: Uint8Array): Uint8Array {
  return new Uint8Array(sha3_256.array(message));
}
