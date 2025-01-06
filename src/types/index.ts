export interface EncryptionKey {
  privateKey: string;
  publicKey: string;
}

export interface ReEncryptionKey {
  key: bigint;
  pubX: Uint8Array;
}

export interface EncryptedData {
  data: Uint8Array;
  capsule: Capsule;
}

export interface ReEncryptedData extends EncryptedData {
  reEncryptionKey: ReEncryptionKey;
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

export interface DecryptParams {
  privateKey: Uint8Array; // bPriKey
  capsule: Capsule;
  pubX: Uint8Array;
  cipherText: Uint8Array;
}
