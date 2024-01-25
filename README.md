# viem-kms-signer

This is a wallet or signer that can be used together with [Viem](https://viem.sh/) applications.

## Getting Started

```ts
import { KmsSigner } from 'viem-kms-signer';

const kmsCredentials = {
  accessKeyId: 'AKIAxxxxxxxxxxxxxxxx', // credentials for your IAM user with KMS access
  secretAccessKey: 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', // credentials for your IAM user with KMS access
  region: 'ap-southeast-1',
  keyId:
    'arn:aws:kms:ap-southeast-1:123456789012:key/123a1234-1234-4111-a1ab-a1abc1a12b12',
};
const signer = new KmsSigner(kmsCredentials);

// Returns a custom viem account instance
const account = await signer.getAccount();
```
