export interface EncryptionKey {
  privateKey: string;
  publicKey: string;
}

export interface ReEncryptionKey {
  key: Uint8Array;
}

export interface EncryptedData {
  data: Uint8Array;
  capsule: Uint8Array;
}

export interface ReEncryptedData extends EncryptedData {
  reEncryptionKey: ReEncryptionKey;
}
