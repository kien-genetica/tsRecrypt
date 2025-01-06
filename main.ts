import { Keypair } from "./src/core/keypair";

async function main() {
  const privateKey =
    "9a11a332de34ad4111c582999b59649f3b23f850a928188d057ae6060e21c23c";

  const keyPair = await Keypair.fromPrivateKey(privateKey);

  console.log("Private Key:", keyPair.privateKey);
  console.log("Public Key:", keyPair.publicKey);
}

main();
