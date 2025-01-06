import { Keypair } from "./src/core/keypair";
import { Encryption } from "./src/core/encryption";

async function main() {
  const priETest =
    "f41f61f79d4853da544021b0cf00dcfd1ae581731e57084678a9c240d1178b6a";
  const priVTest =
    "83a49bd850c4608b82d7525bd6f8680c02208393c05a5df79e7c21f542bd4e2a";

  Encryption.encryptKeygen(priETest, priVTest);
}

main();
