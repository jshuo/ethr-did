import { ES256KSigner, hexToBytes, ES256Signer, createJWT, verifyJWT } from 'did-jwt';
import { computeAddress } from '@ethersproject/transactions';
import { computePublicKey } from '@ethersproject/signing-key';
import { Wallet } from '@ethersproject/wallet';
import * as base64 from '@ethersproject/base64';
import { hexValue, isBytes, hexlify } from '@ethersproject/bytes';
import { Base58 } from '@ethersproject/basex';
import { toUtf8Bytes } from '@ethersproject/strings';
import { interpretIdentifier, EthrDidController, REGISTRY } from 'ethr-did-resolver';
import { ec } from 'elliptic';

function _extends() {
  _extends = Object.assign ? Object.assign.bind() : function (target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = arguments[i];

      for (var key in source) {
        if (Object.prototype.hasOwnProperty.call(source, key)) {
          target[key] = source[key];
        }
      }
    }

    return target;
  };
  return _extends.apply(this, arguments);
}

var DelegateTypes;

(function (DelegateTypes) {
  DelegateTypes["veriKey"] = "veriKey";
  DelegateTypes["sigAuth"] = "sigAuth";
  DelegateTypes["enc"] = "enc";
})(DelegateTypes || (DelegateTypes = {}));

class EthrDID {
  constructor(conf) {
    this.did = void 0;
    this.address = void 0;
    this.signer = void 0;
    this.alg = void 0;
    this.owner = void 0;
    this.controller = void 0;
    const {
      address,
      publicKey,
      network
    } = interpretIdentifier(conf.identifier);
    const chainNameOrId = typeof conf.chainNameOrId === 'number' ? hexValue(conf.chainNameOrId) : conf.chainNameOrId;

    if (conf.provider || conf.rpcUrl || conf.web3) {
      var _conf$web;

      let txSigner = conf.txSigner;

      if (conf.privateKey && typeof txSigner === 'undefined') {
        txSigner = new Wallet(conf.privateKey);
      }

      this.controller = new EthrDidController(conf.identifier, undefined, txSigner, chainNameOrId, conf.provider || ((_conf$web = conf.web3) == null ? void 0 : _conf$web.currentProvider), conf.rpcUrl, conf.registry || REGISTRY);
      this.did = this.controller.did;
    } else {
      const net = network || chainNameOrId;
      let networkString = net ? `${net}:` : '';

      if (networkString in ['mainnet:', '0x1:']) {
        networkString = '';
      }

      this.did = typeof publicKey === 'string' ? `did:ethr:${networkString}${publicKey}` : `did:ethr:${networkString}${address}`;
    }

    this.address = address;

    if (conf.signer) {
      this.signer = conf.signer;
      this.alg = conf.alg;

      if (!this.alg) {
        console.warn('A JWT signer was specified but no algorithm was set. Please set the `alg` parameter when calling `new EthrDID()`');
      }
    } else if (conf.privateKey) {
      this.signer = ES256KSigner(hexToBytes(conf.privateKey), true);
      this.alg = 'ES256K-R';
    }
  }

  static createKeyPair(chainNameOrId) {
    const ec$1 = new ec('p256'); // 'p256' is another name for secp256r1
    // Generate a key pair

    const keyPair = ec$1.genKeyPair();
    const privateKey = '0x' + keyPair.getPrivate('hex');
    const address = computeAddress(privateKey);
    const publicKey = computePublicKey(privateKey, true);
    const net = typeof chainNameOrId === 'number' ? hexValue(chainNameOrId) : chainNameOrId;
    const identifier = net ? `did:ethr:${net}:${publicKey}` : publicKey;
    return {
      address,
      privateKey,
      publicKey,
      identifier
    };
  }

  async lookupOwner(cache = true) {
    var _this$controller;

    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    if (cache && this.owner) return this.owner;
    return (_this$controller = this.controller) == null ? void 0 : _this$controller.getOwner(this.address);
  }

  async changeOwner(newOwner, txOptions) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const owner = await this.lookupOwner();
    const receipt = await this.controller.changeOwner(newOwner, _extends({}, txOptions, {
      from: owner
    }));
    this.owner = newOwner;
    return receipt.transactionHash;
  }

  async createChangeOwnerHash(newOwner) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    return this.controller.createChangeOwnerHash(newOwner);
  }

  async changeOwnerSigned(newOwner, signature, txOptions) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const receipt = await this.controller.changeOwnerSigned(newOwner, signature, txOptions);
    this.owner = newOwner;
    return receipt.transactionHash;
  }

  async addDelegate(delegate, delegateOptions, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const owner = await this.lookupOwner();
    const receipt = await this.controller.addDelegate((delegateOptions == null ? void 0 : delegateOptions.delegateType) || DelegateTypes.veriKey, delegate, (delegateOptions == null ? void 0 : delegateOptions.expiresIn) || 86400, _extends({}, txOptions, {
      from: owner
    }));
    return receipt.transactionHash;
  }

  async createAddDelegateHash(delegateType, delegateAddress, exp) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    return this.controller.createAddDelegateHash(delegateType, delegateAddress, exp);
  }

  async addDelegateSigned(delegate, signature, delegateOptions, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const receipt = await this.controller.addDelegateSigned((delegateOptions == null ? void 0 : delegateOptions.delegateType) || DelegateTypes.veriKey, delegate, (delegateOptions == null ? void 0 : delegateOptions.expiresIn) || 86400, signature, txOptions);
    return receipt.transactionHash;
  }

  async revokeDelegate(delegate, delegateType = DelegateTypes.veriKey, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const owner = await this.lookupOwner();
    const receipt = await this.controller.revokeDelegate(delegateType, delegate, _extends({}, txOptions, {
      from: owner
    }));
    return receipt.transactionHash;
  }

  async createRevokeDelegateHash(delegateType, delegateAddress) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    return this.controller.createRevokeDelegateHash(delegateType, delegateAddress);
  }

  async revokeDelegateSigned(delegate, delegateType = DelegateTypes.veriKey, signature, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const receipt = await this.controller.revokeDelegateSigned(delegateType, delegate, signature, txOptions);
    return receipt.transactionHash;
  }

  async setAttribute(key, value, expiresIn = 86400,
  /** @deprecated please use `txOptions.gasLimit` */
  gasLimit, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const owner = await this.lookupOwner();
    const receipt = await this.controller.setAttribute(key, attributeToHex(key, value), expiresIn, _extends({
      gasLimit
    }, txOptions, {
      from: owner
    }));
    return receipt.transactionHash;
  }

  async createSetAttributeHash(attrName, attrValue, exp) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    return this.controller.createSetAttributeHash(attrName, attrValue, exp);
  }

  async setAttributeSigned(key, value, expiresIn = 86400, signature, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const receipt = await this.controller.setAttributeSigned(key, attributeToHex(key, value), expiresIn, signature, txOptions);
    return receipt.transactionHash;
  }

  async revokeAttribute(key, value,
  /** @deprecated please use `txOptions.gasLimit` */
  gasLimit, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const owner = await this.lookupOwner();
    const receipt = await this.controller.revokeAttribute(key, attributeToHex(key, value), _extends({
      gasLimit
    }, txOptions, {
      from: owner
    }));
    return receipt.transactionHash;
  }

  async createRevokeAttributeHash(attrName, attrValue) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    return this.controller.createRevokeAttributeHash(attrName, attrValue);
  }

  async revokeAttributeSigned(key, value, signature, txOptions = {}) {
    if (typeof this.controller === 'undefined') {
      throw new Error('a web3 provider configuration is needed for network operations');
    }

    const receipt = await this.controller.revokeAttributeSigned(key, attributeToHex(key, value), signature, txOptions);
    return receipt.transactionHash;
  } // Create a temporary signing delegate able to sign JWT on behalf of identity


  async createSigningDelegate(delegateType = DelegateTypes.veriKey, expiresIn = 86400) {
    const kp = EthrDID.createKeyPair();
    this.signer = ES256Signer(hexToBytes(kp.privateKey));
    const txHash = await this.addDelegate(kp.address, {
      delegateType,
      expiresIn
    });
    return {
      kp,
      txHash
    };
  } // eslint-disable-next-line


  async signJWT(payload, expiresIn) {
    if (typeof this.signer !== 'function') {
      throw new Error('No signer configured');
    }

    const options = {
      signer: this.signer,
      alg: 'ES256',
      issuer: this.did
    }; // eslint-disable-next-line @typescript-eslint/no-explicit-any

    if (expiresIn) options['expiresIn'] = expiresIn;
    return createJWT(payload, options);
  }

  async verifyJWT(jwt, resolver, audience = this.did) {
    return verifyJWT(jwt, {
      resolver,
      audience
    });
  }

}

function attributeToHex(key, value) {
  if (value instanceof Uint8Array || isBytes(value)) {
    return hexlify(value);
  }

  const matchKeyWithEncoding = key.match(/^did\/(pub|auth|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
  const encoding = matchKeyWithEncoding == null ? void 0 : matchKeyWithEncoding[6];
  const matchHexString = value.match(/^0x[0-9a-fA-F]*$/);

  if (encoding && !matchHexString) {
    if (encoding === 'base64') {
      return hexlify(base64.decode(value));
    }

    if (encoding === 'base58') {
      return hexlify(Base58.decode(value));
    }
  } else if (matchHexString) {
    return value;
  }

  return hexlify(toUtf8Bytes(value));
}

export { DelegateTypes, EthrDID };
//# sourceMappingURL=index.modern.js.map
