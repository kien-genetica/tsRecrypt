import { Capsule } from "../types";

/**
 * Converts a bigint to a hex string
 * @param n The bigint to convert
 * @returns Hex string representation
 */
export function bigintToHex(n: bigint): string {
  return n.toString(16).padStart(64, "0");
}

export function hexToBigint(hex: string): bigint {
  // Remove 0x prefix if present
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  return BigInt(`0x${cleanHex}`);
}

export function encodeCapsuleToHex(capsule: Capsule): string {
  // Convert to a serializable object
  const serializableObj = {
    E: capsule.E,
    V: capsule.V,
    S: capsule.S.toString(16), // convert bigint to hex string
  };

  // Convert to JSON string then to hex
  const jsonStr = JSON.stringify(serializableObj);
  return Buffer.from(jsonStr).toString("hex");
}

export function decodeCapsuleFromHex(hexStr: string): Capsule {
  // Convert hex to JSON string
  const jsonStr = Buffer.from(hexStr, "hex").toString();
  const obj = JSON.parse(jsonStr);

  // Convert back to Capsule type
  return {
    E: obj.E,
    V: obj.V,
    S: BigInt(`0x${obj.S}`),
  };
}
