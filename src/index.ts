import { LocalAccount, signTypedData, toAccount } from 'viem/accounts';
import {
  determineCorrectV,
  getEthereumAddress,
  getPublicKey,
  requestKmsSignature,
} from './utils/kms-utils';
import {
  Signature,
  TransactionSerializable,
  hashMessage,
  keccak256,
  serializeTransaction,
  signatureToHex,
} from 'viem';

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

  // async getAccount(): Promise<LocalAccount> {
  //   const address = await this.getAddress();

  //   return toAccount({
  //     address,
  //     async signMessage({ message }): Promise<`0x${string}`> {
  //       return await this._signDigestHex(hashMessage(message));
  //     },
  //     async signTransaction(transaction) {
  //       return await this._signTransaction(transaction);
  //     },
  //     async signTypedData(typedData) {
  //       return signTypedData({ ...typedData, privateKey: '0x' });
  //     },
  //   });
  // }

  async getAddress(): Promise<`0x${string}`> {
    if (this.ethereumAddress === undefined) {
      const key = await getPublicKey(this.kmsCredentials);
      this.ethereumAddress = getEthereumAddress(Buffer.from(key.PublicKey));
    }
    return Promise.resolve(this.ethereumAddress);
  }

  private async _signTransaction(
    transaction: TransactionSerializable,
  ): Promise<string> {
    const serializedTx = serializeTransaction(transaction);
    const transactionSignature = await this._signDigest(
      keccak256(serializedTx),
    );
    return serializeTransaction(transaction, transactionSignature);
  }

  private async _signDigest(digestString: string): Promise<Signature> {
    const digestBuffer = Buffer.from(digestString.slice(2), 'hex');
    const sig = await requestKmsSignature(digestBuffer, this.kmsCredentials);
    const ethAddr = await this.getAddress();
    const { v } = await determineCorrectV(digestBuffer, sig.r, sig.s, ethAddr);
    return {
      r: `0x${sig.r.toString('hex')}`,
      s: `0x${sig.s.toString('hex')}`,
      v: BigInt(v),
    };
  }

  private async _signDigestHex(digestString: string): Promise<string> {
    return signatureToHex(await this._signDigest(digestString));
  }
}
