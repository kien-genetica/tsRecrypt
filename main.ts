import { Keypair } from "./src/core/keypair";
import { Encryption } from "./src/core/encryption";
import * as utils from "./src/core/utils";
async function main() {
  const alicePrivateKey =
    "f41f61f79d4853da544021b0cf00dcfd1ae581731e57084678a9c240d1178b6a";
  const bobPrivateKey =
    "edefc6565e4de87f49a4e2f1866a28eae6d9b75cdc4a6a5249d1e7c54f8076b2";

  const bobPrivateKeyBytes = Encryption.hexToBytes(bobPrivateKey);
  const bobPublicKey = Encryption.getUncompressedPublicKey(bobPrivateKeyBytes);
  console.log("bobPublicKey:", Encryption.bytesToHex(bobPublicKey));

  const alicePrivateKeyBytes = Encryption.hexToBytes(alicePrivateKey);
  const alicePublicKey =
    Encryption.getUncompressedPublicKey(alicePrivateKeyBytes);
  console.log("alicePublicKey:", Encryption.bytesToHex(alicePublicKey));
  const data = "Hello, world!";
  const encryptedData = await Encryption.encrypt(
    Buffer.from(data),
    alicePublicKey
  );
  console.log("encryptedData:", encryptedData.data);
  console.log("encryptedData:", Encryption.bytesToHex(encryptedData.data));

  console.log("\n===== encrypt =====");
  console.log("capsule E:", encryptedData.capsule.E);
  console.log("capsule V:", encryptedData.capsule.V);
  console.log("capsule S:", encryptedData.capsule.S);
  console.log("data:", Encryption.bytesToHex(encryptedData.data));
  console.log("capsule hex:", utils.encodeCapsuleToHex(encryptedData.capsule));

  // Generate re-encryption key
  console.log("\n===== generate re-encryption key =====");
  const reEncryptionKey = Encryption.generateReEncryptionKey(
    Encryption.hexToBytes(alicePrivateKey),
    bobPublicKey
  );

  console.log("reEncryptionKey hex:", utils.bigintToHex(reEncryptionKey.key));
  console.log(
    "reEncryptionKey bigint:",
    utils.hexToBigint(utils.bigintToHex(reEncryptionKey.key))
  );
  console.log(
    "reEncryptionKey pubX:",
    Encryption.bytesToHex(reEncryptionKey.pubX)
  );

  // re-encrypt
  console.log("\n===== re-encrypt =====");
  const newCapsule = await Encryption.reEncrypt(
    reEncryptionKey.key,
    encryptedData.capsule
  );

  console.log("newCapsule E:", newCapsule.E);
  console.log("newCapsule V:", newCapsule.V);
  console.log("newCapsule S:", newCapsule.S);
  console.log("newCapsule hex:", utils.encodeCapsuleToHex(newCapsule));
  console.log(
    "newCapsule hexToCapsule:",
    utils.decodeCapsuleFromHex(utils.encodeCapsuleToHex(newCapsule))
  );
  // decrypt
  console.log("\n===== decrypt =====");
  const decrypted = await Encryption.decrypt({
    privateKey: Encryption.hexToBytes(bobPrivateKey),
    capsule: newCapsule,
    pubX: reEncryptionKey.pubX,
    cipherText: encryptedData.data,
  });
  console.log("decrypted:", decrypted.toString());
}

main();
