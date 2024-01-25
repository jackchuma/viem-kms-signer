import { toAccount } from 'viem/accounts';
import { getEthereumAddress, getPublicKey } from './utils/kms-utils';

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

  // async getAccount() {
  //   const address = await this.getAddress();

  //   return toAccount({
  //     address,
  //     async signMessage({ message }) {},
  //     async signTransaction(transaction, { serializer }) {},
  //     async signTypedData(typedData) {},
  //   });
  // }

  async getAddress(): Promise<`0x${string}`> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.kmsCredentials);
      this.ethereumAddress = getEthereumAddress(Buffer.from(key.PublicKey));
    }
    return Promise.resolve(this.ethereumAddress);
  }
}
