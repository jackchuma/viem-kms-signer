import { KmsSigner } from '.';
import dotenv from 'dotenv';
dotenv.config();

async function main() {
  const credentials = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID as string,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY as string,
    region: process.env.AWS_REGION as string,
    keyId: process.env.AWS_KEY_ID as string,
  };
  const signer = new KmsSigner(credentials);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
