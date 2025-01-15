import { ethers } from "ethers";
import {
  EncryptionKey,
  EncryptedData,
  ReEncryptionKey,
  ReEncryptedData,
  Capsule,
  EncryptKeyGen,
  DecryptParams,
} from "../types";
import { secp256k1 } from "@noble/curves/secp256k1";
import { mod } from "@noble/curves/abstract/modular";
import * as fs from "fs";

import { sha3_256 } from "js-sha3";
import { webcrypto } from "crypto";
const crypto = webcrypto;

export class Encryption {
  /**
   * Encrypts data using recipient's public key
   */
  static async encrypt(
    data: Buffer,
    recipientPublicKey: Uint8Array,
    privETest: string,
    privVTest: string
  ): Promise<EncryptedData> {
    const encryptKeyGen = Encryption.encryptKeygen(
      recipientPublicKey,
      privETest,
      privVTest
    );

    const keyBytes = Encryption.hexToBytes(encryptKeyGen.aesKey);
    const key = encryptKeyGen.aesKey.slice(0, 32); // Take first 32 chars of hex string
    const nonce = keyBytes.slice(0, 12); // Take first 12 bytes as nonce

    const encoder = new TextEncoder();
    // Import key propefrly for AES-GCM
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
      data
    );

    const ciphertextBytes = new Uint8Array(ciphertext);
    return {
      data: ciphertextBytes,
      capsule: encryptKeyGen.Capsule,
    };
  }

  static async encryptFile(
    inputFile: string, // Changed from Buffer to string to match Go
    outputFile: string,
    recipientPublicKey: Uint8Array,
    priETest: string,
    priVTest: string
  ): Promise<Capsule> {
    // Generate encryption key
    const encryptKeyGen = Encryption.encryptKeygen(
      recipientPublicKey,
      priETest,
      priVTest
    );

    const keyBytes = Encryption.hexToBytes(encryptKeyGen.aesKey);
    const key = encryptKeyGen.aesKey.slice(0, 32);
    const nonce = keyBytes.slice(0, 16);

    // Read input file
    const inFile = await fs.promises.readFile(inputFile);

    // Create cipher
    const block = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      { name: "AES-CTR" }, // Using CTR as closest to OFB
      false,
      ["encrypt"]
    );

    // Encrypt file
    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-CTR",
        counter: nonce,
        length: 128,
      },
      block,
      inFile
    );

    // Write to output file
    await fs.promises.writeFile(outputFile, Buffer.from(encrypted));

    return encryptKeyGen.Capsule;
  }

  static generateReEncryptionKey(
    delegatorPrivateKey: Uint8Array, // aPriKey
    delegateePublicKey: Uint8Array, // bPubKey
    privXTest: string // x_A
  ): ReEncryptionKey {
    // Generate x,X key-pair
    // const priX = Encryption.hexToBytes(privXTest);
    // const pubX = secp256k1.getPublicKey(priX, false);

    // calculate x_a, X_a
    const priX = Encryption.hexToBytes(privXTest);
    const pubX = Encryption.getUncompressedPublicKey(priX);

    // Get private x_a bignumber
    const priXBig = BigInt("0x" + Encryption.bytesToHex(priX));

    // Calculate pk_B^x_A
    const point = Encryption.pointScalarMul(delegateePublicKey, priXBig);
    console.log("point:", Encryption.bytesToHex(point));

    // Calculate d = H3(X_A || pk_B || point)
    // Concatenate X_A || pk_B || point
    const concatenated = Encryption.concatBytes(
      Encryption.concatBytes(pubX, delegateePublicKey),
      point
    );

    // Hash to curve
    const d = Encryption.hashToCurve(concatenated);

    // Calculate rk = sk_A * d^(-1)
    const delegatorPrivKeyBig = BigInt(
      "0x" + Encryption.bytesToHex(delegatorPrivateKey)
    );
    const dInverse = modInverse(d, secp256k1.CURVE.n);
    const rk = (delegatorPrivKeyBig * dInverse) % secp256k1.CURVE.n;

    return {
      key: rk,
      pubX: pubX,
    };
  }

  static async reEncrypt(rk: bigint, capsule: Capsule): Promise<Capsule> {
    // Check g^s == V * E^{H2(E || V)}
    const basePoint = secp256k1.ProjectivePoint.BASE;
    const gs = basePoint.multiply(capsule.S);

    // Calculate H2(E || V)
    const concatenated = Encryption.concatBytes(
      Encryption.hexToBytes(capsule.E),
      Encryption.hexToBytes(capsule.V)
    );
    const h = Encryption.hashToCurve(concatenated);

    // Add '04' prefix for uncompressed point format if not present
    const eHex = capsule.E.startsWith("04") ? capsule.E : "04" + capsule.E;
    const vHex = capsule.V.startsWith("04") ? capsule.V : "04" + capsule.V;

    // Calculate E^h
    const E = secp256k1.ProjectivePoint.fromHex(eHex);
    const Eh = E.multiply(h);

    // Calculate V * E^h
    const V = secp256k1.ProjectivePoint.fromHex(vHex);
    const VEh = V.add(Eh);

    // Verify g^s == V * E^h
    if (!gs.equals(VEh)) {
      throw new Error("Capsule not match");
    }

    // E' = E^{rk}, V' = V^{rk}
    const newE = E.multiply(rk);
    const newV = V.multiply(rk);

    return {
      E: Encryption.bytesToHex(newE.toRawBytes(false)),
      V: Encryption.bytesToHex(newV.toRawBytes(false)),
      S: capsule.S,
    };
  }

  /**
   * Decrypts data using recipient's private key
   */
  static async decrypt({
    privateKey,
    capsule,
    pubX,
    cipherText,
  }: DecryptParams): Promise<Buffer> {
    // Generate decryption key
    const keyBytes = await Encryption.decryptKeyGen(privateKey, capsule, pubX);
    console.log("keyBytes:", Encryption.bytesToHex(keyBytes));
    // Get key and nonce for AES-GCM
    const key = Encryption.bytesToHex(keyBytes).slice(0, 32);
    const nonce = keyBytes.slice(0, 12);

    // Import key for AES-GCM
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(key),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    // Decrypt using AES-GCM
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
      },
      cryptoKey,
      cipherText
    );

    // Convert decrypted bytes to string
    return Buffer.from(decrypted);
  }

  private static async decryptKeyGen(
    privateKey: Uint8Array,
    capsule: Capsule,
    pubX: Uint8Array
  ): Promise<Uint8Array> {
    // S = X_A^{sk_B}
    const privKeyBig = BigInt("0x" + Encryption.bytesToHex(privateKey));

    const S = Encryption.pointScalarMul(pubX, privKeyBig);

    console.log("S:", Encryption.bytesToHex(S));

    // Recreate d = H3(X_A || pk_B || S)
    const publicKey = Encryption.getUncompressedPublicKey(privateKey);
    const concatenated = Encryption.concatBytes(
      Encryption.concatBytes(pubX, publicKey),
      S
    );
    const d = Encryption.hashToCurve(concatenated);

    // Calculate point = (E' * V')^d
    const E = secp256k1.ProjectivePoint.fromHex(capsule.E);
    const V = secp256k1.ProjectivePoint.fromHex(capsule.V);
    const EV = E.add(V);
    const point = EV.multiply(d);

    // Generate AES key
    return sha3Hash(point.toRawBytes(false));
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
        E: Encryption.bytesToHex(pubE),
        V: Encryption.bytesToHex(pubV),
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

// TODO: find out how it work
function modInverse(a: bigint, m: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = m;
  let newR = a;

  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }

  if (t < 0n) t += m;
  return t;
}
