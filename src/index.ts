import { LocalAccount, toAccount } from 'viem/accounts';
import {
  getEthereumAddress,
  getPublicKey,
  signDigestHex,
  signTransaction,
} from './utils/kms-utils';
import { hashMessage, hashTypedData } from 'viem';

export interface AwsKmsSignerCredentials {
  accessKeyId?: string;
  secretAccessKey?: string;
  sessionToken?: string;
  region: string;
  keyId: string;
}

export class KmsSigner {
  private readonly kmsCredentials: AwsKmsSignerCredentials;
  private ethereumAddress: `0x${string}`;

  constructor(kmsCredentials: AwsKmsSignerCredentials) {
    this.kmsCredentials = kmsCredentials;
  }

  async getAccount(): Promise<LocalAccount> {
    const address = await this.getAddress();
    const credentials = this.kmsCredentials;

    return toAccount({
      address,
      async signMessage({ message }): Promise<`0x${string}`> {
        return await signDigestHex(hashMessage(message), credentials, address);
      },
      async signTransaction(transaction): Promise<`0x${string}`> {
        return await signTransaction(transaction, credentials, address);
      },
      async signTypedData(typedData): Promise<`0x${string}`> {
        return await signDigestHex(
          hashTypedData(typedData),
          credentials,
          address,
        );
      },
    });
  }

  async getAddress(): Promise<`0x${string}`> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.kmsCredentials);
      this.ethereumAddress = getEthereumAddress(Buffer.from(key.PublicKey));
    }
    return Promise.resolve(this.ethereumAddress);
  }
}
