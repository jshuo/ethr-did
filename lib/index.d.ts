import { JWTVerified, Signer as JWTSigner } from 'did-jwt';
import { Signer as TxSigner } from '@ethersproject/abstract-signer';
import { CallOverrides } from '@ethersproject/contracts';
import { Provider } from '@ethersproject/providers';
import { MetaSignature } from 'ethr-did-resolver';
import { Resolvable } from 'did-resolver';
export declare enum DelegateTypes {
    veriKey = "veriKey",
    sigAuth = "sigAuth",
    enc = "enc"
}
interface IConfig {
    identifier: string;
    chainNameOrId?: string | number;
    registry?: string;
    signer?: JWTSigner;
    alg?: 'ES256K' | 'ES256K-R';
    txSigner?: TxSigner;
    privateKey?: string;
    rpcUrl?: string;
    provider?: Provider;
    web3?: any;
}
export declare type KeyPair = {
    address: string;
    privateKey: string;
    publicKey: string;
    identifier: string;
};
declare type DelegateOptions = {
    delegateType?: DelegateTypes;
    expiresIn?: number;
};
export declare class EthrDID {
    did: string;
    address: string;
    signer?: JWTSigner;
    alg?: 'ES256K' | 'ES256K-R';
    private owner?;
    private controller?;
    constructor(conf: IConfig);
    static createKeyPair(chainNameOrId?: string | number): KeyPair;
    lookupOwner(cache?: boolean): Promise<string>;
    changeOwner(newOwner: string, txOptions?: CallOverrides): Promise<string>;
    createChangeOwnerHash(newOwner: string): Promise<string>;
    changeOwnerSigned(newOwner: string, signature: MetaSignature, txOptions: CallOverrides): Promise<string>;
    addDelegate(delegate: string, delegateOptions?: DelegateOptions, txOptions?: CallOverrides): Promise<string>;
    createAddDelegateHash(delegateType: string, delegateAddress: string, exp: number): Promise<string>;
    addDelegateSigned(delegate: string, signature: MetaSignature, delegateOptions?: DelegateOptions, txOptions?: CallOverrides): Promise<string>;
    revokeDelegate(delegate: string, delegateType?: DelegateTypes, txOptions?: CallOverrides): Promise<string>;
    createRevokeDelegateHash(delegateType: string, delegateAddress: string): Promise<string>;
    revokeDelegateSigned(delegate: string, delegateType: DelegateTypes | undefined, signature: MetaSignature, txOptions?: CallOverrides): Promise<string>;
    setAttribute(key: string, value: string | Uint8Array, expiresIn?: number, 
    /** @deprecated please use `txOptions.gasLimit` */
    gasLimit?: number, txOptions?: CallOverrides): Promise<string>;
    createSetAttributeHash(attrName: string, attrValue: string, exp: number): Promise<string>;
    setAttributeSigned(key: string, value: string | Uint8Array, expiresIn: number | undefined, signature: MetaSignature, txOptions?: CallOverrides): Promise<string>;
    revokeAttribute(key: string, value: string | Uint8Array, 
    /** @deprecated please use `txOptions.gasLimit` */
    gasLimit?: number, txOptions?: CallOverrides): Promise<string>;
    createRevokeAttributeHash(attrName: string, attrValue: string): Promise<string>;
    revokeAttributeSigned(key: string, value: string | Uint8Array, signature: MetaSignature, txOptions?: CallOverrides): Promise<string>;
    createSigningDelegate(delegateType: DelegateTypes | undefined, expiresIn: number | undefined, pufHsmRemoteUrl: string): Promise<{
        address: string;
        pubkey: string;
        txHash: string;
    }>;
    signJWT(payload: any, expiresIn?: number, pufHsmRemoteUrl?: string): Promise<string>;
    verifyJWT(jwt: string, resolver: Resolvable, audience?: string): Promise<JWTVerified>;
}
export {};
//# sourceMappingURL=index.d.ts.map