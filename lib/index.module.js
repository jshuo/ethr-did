import { ES256KSigner, hexToBytes, toEthereumAddress, ES256HSMSigner, ES256Signer, createJWT, verifyJWT } from 'did-jwt';
import { Wallet } from '@ethersproject/wallet';
import * as base64 from '@ethersproject/base64';
import { hexValue, isBytes, hexlify } from '@ethersproject/bytes';
import { Base58 } from '@ethersproject/basex';
import { toUtf8Bytes } from '@ethersproject/strings';
import { interpretIdentifier, EthrDidController, REGISTRY } from 'ethr-did-resolver';
import { ec } from 'elliptic';

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
      let txSigner = conf.txSigner;
      if (conf.privateKey && typeof txSigner === 'undefined') {
        txSigner = new Wallet(conf.privateKey);
      }
      this.controller = new EthrDidController(conf.identifier, undefined, txSigner, chainNameOrId, conf.provider || conf.web3?.currentProvider, conf.rpcUrl, conf.registry || REGISTRY);
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
    // var key = ec.genKeyPair();
    // const privateKey = '0x' + key.getPrivate('hex');
    // hard code privatekey for fixing
    const privateKey = '736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8';
    const key = ec$1.keyFromPrivate(privateKey);
    const publicKey = key.getPublic().encode("hex", false);
    const address = toEthereumAddress(publicKey);
    const net = typeof chainNameOrId === 'number' ? hexValue(chainNameOrId) : chainNameOrId;
    const identifier = net ? `did:ethr:${net}:${publicKey}` : publicKey;
    return {
      address,
      privateKey,
      publicKey,
      identifier
    };
  }
  lookupOwner(cache = true) {
    try {
      const _this = this;
      if (typeof _this.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      if (cache && _this.owner) return Promise.resolve(_this.owner);
      return Promise.resolve(_this.controller?.getOwner(_this.address));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  changeOwner(newOwner, txOptions) {
    try {
      const _this2 = this;
      if (typeof _this2.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this2.lookupOwner()).then(function (owner) {
        return Promise.resolve(_this2.controller.changeOwner(newOwner, {
          ...txOptions,
          from: owner
        })).then(function (receipt) {
          _this2.owner = newOwner;
          return receipt.transactionHash;
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  createChangeOwnerHash(newOwner) {
    try {
      const _this3 = this;
      if (typeof _this3.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this3.controller.createChangeOwnerHash(newOwner));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  changeOwnerSigned(newOwner, signature, txOptions) {
    try {
      const _this4 = this;
      if (typeof _this4.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this4.controller.changeOwnerSigned(newOwner, signature, txOptions)).then(function (receipt) {
        _this4.owner = newOwner;
        return receipt.transactionHash;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  addDelegate(delegate, delegateOptions, txOptions = {}) {
    try {
      const _this5 = this;
      if (typeof _this5.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this5.lookupOwner()).then(function (owner) {
        return Promise.resolve(_this5.controller.addDelegate(delegateOptions?.delegateType || DelegateTypes.veriKey, delegate, delegateOptions?.expiresIn || 86400, {
          ...txOptions,
          from: owner
        })).then(function (receipt) {
          return receipt.transactionHash;
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  createAddDelegateHash(delegateType, delegateAddress, exp) {
    try {
      const _this6 = this;
      if (typeof _this6.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this6.controller.createAddDelegateHash(delegateType, delegateAddress, exp));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  addDelegateSigned(delegate, signature, delegateOptions, txOptions = {}) {
    try {
      const _this7 = this;
      if (typeof _this7.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this7.controller.addDelegateSigned(delegateOptions?.delegateType || DelegateTypes.veriKey, delegate, delegateOptions?.expiresIn || 86400, signature, txOptions)).then(function (receipt) {
        return receipt.transactionHash;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  revokeDelegate(delegate, delegateType, txOptions = {}) {
    try {
      const _this8 = this;
      if (delegateType === undefined) delegateType = DelegateTypes.veriKey;
      if (typeof _this8.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this8.lookupOwner()).then(function (owner) {
        return Promise.resolve(_this8.controller.revokeDelegate(delegateType, delegate, {
          ...txOptions,
          from: owner
        })).then(function (receipt) {
          return receipt.transactionHash;
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  createRevokeDelegateHash(delegateType, delegateAddress) {
    try {
      const _this9 = this;
      if (typeof _this9.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this9.controller.createRevokeDelegateHash(delegateType, delegateAddress));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  revokeDelegateSigned(delegate, delegateType, signature, txOptions = {}) {
    try {
      const _this10 = this;
      if (delegateType === undefined) delegateType = DelegateTypes.veriKey;
      if (typeof _this10.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this10.controller.revokeDelegateSigned(delegateType, delegate, signature, txOptions)).then(function (receipt) {
        return receipt.transactionHash;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  setAttribute(key, value, expiresIn = 86400, /** @deprecated please use `txOptions.gasLimit` */
  gasLimit, txOptions = {}) {
    try {
      const _this11 = this;
      if (typeof _this11.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this11.lookupOwner()).then(function (owner) {
        return Promise.resolve(_this11.controller.setAttribute(key, attributeToHex(key, value), expiresIn, {
          gasLimit,
          ...txOptions,
          from: owner
        })).then(function (receipt) {
          return receipt.transactionHash;
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  createSetAttributeHash(attrName, attrValue, exp) {
    try {
      const _this12 = this;
      if (typeof _this12.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this12.controller.createSetAttributeHash(attrName, attrValue, exp));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  setAttributeSigned(key, value, expiresIn = 86400, signature, txOptions = {}) {
    try {
      const _this13 = this;
      if (typeof _this13.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this13.controller.setAttributeSigned(key, attributeToHex(key, value), expiresIn, signature, txOptions)).then(function (receipt) {
        return receipt.transactionHash;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  revokeAttribute(key, value, /** @deprecated please use `txOptions.gasLimit` */
  gasLimit, txOptions = {}) {
    try {
      const _this14 = this;
      if (typeof _this14.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this14.lookupOwner()).then(function (owner) {
        return Promise.resolve(_this14.controller.revokeAttribute(key, attributeToHex(key, value), {
          gasLimit,
          ...txOptions,
          from: owner
        })).then(function (receipt) {
          return receipt.transactionHash;
        });
      });
    } catch (e) {
      return Promise.reject(e);
    }
  }
  createRevokeAttributeHash(attrName, attrValue) {
    try {
      const _this15 = this;
      if (typeof _this15.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this15.controller.createRevokeAttributeHash(attrName, attrValue));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  revokeAttributeSigned(key, value, signature, txOptions = {}) {
    try {
      const _this16 = this;
      if (typeof _this16.controller === 'undefined') {
        throw new Error('a web3 provider configuration is needed for network operations');
      }
      return Promise.resolve(_this16.controller.revokeAttributeSigned(key, attributeToHex(key, value), signature, txOptions)).then(function (receipt) {
        return receipt.transactionHash;
      });
    } catch (e) {
      return Promise.reject(e);
    }
  } // Create a temporary signing delegate able to sign JWT on behalf of identity
  createSigningDelegate(delegateType, expiresIn = 86400, pufHsmRemoteUrl) {
    try {
      let _exit;
      const _this17 = this;
      function _temp2(_result) {
        return _exit ? _result : Promise.resolve(_this17.addDelegate(address, {
          delegateType,
          expiresIn
        })).then(function (txHash) {
          return {
            address,
            pubkey,
            txHash
          };
        });
      }
      if (delegateType === undefined) delegateType = DelegateTypes.veriKey;
      let address, pubkey;
      const _temp = function () {
        if (typeof pufHsmRemoteUrl === 'string') {
          return Promise.resolve(fetch(`${pufHsmRemoteUrl}pufs_get_p256_pubkey_js`)).then(function (response) {
            if (!response.ok) {
              throw new Error(`createSigningDelegate HTTP error! status: ${response.status}`);
            }
            return Promise.resolve(response.text()).then(function (jsonString) {
              pubkey = JSON.parse(jsonString).pubkey;
              address = toEthereumAddress(pubkey);
            });
          });
        } else {
          const kp = EthrDID.createKeyPair();
          address = kp.address;
          pubkey = kp.publicKey;
        }
      }();
      return Promise.resolve(_temp && _temp.then ? _temp.then(_temp2) : _temp2(_temp));
    } catch (e) {
      return Promise.reject(e);
    }
  } // eslint-disable-next-line
  signJWT(payload, expiresIn, pufHsmRemoteUrl) {
    try {
      const _this18 = this;
      if (typeof pufHsmRemoteUrl === 'string') {
        _this18.signer = ES256HSMSigner(pufHsmRemoteUrl);
      } else {
        _this18.signer = ES256Signer(hexToBytes("736f625c9dda78a94bb16840c82779bb7bc18014b8ede52f0f03429902fc4ba8"));
      }
      if (typeof _this18.signer !== 'function') {
        throw new Error('No signer configured');
      }
      const options = {
        signer: _this18.signer,
        alg: 'ES256',
        issuer: _this18.did
      };
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      if (expiresIn) options['expiresIn'] = expiresIn;
      return Promise.resolve(createJWT(payload, options));
    } catch (e) {
      return Promise.reject(e);
    }
  }
  verifyJWT(jwt, resolver, audience) {
    try {
      const _this19 = this;
      if (audience === undefined) audience = _this19.did;
      return Promise.resolve(verifyJWT(jwt, {
        resolver,
        audience
      }));
    } catch (e) {
      return Promise.reject(e);
    }
  }
}
function attributeToHex(key, value) {
  if (value instanceof Uint8Array || isBytes(value)) {
    return hexlify(value);
  }
  const matchKeyWithEncoding = key.match(/^did\/(pub|auth|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
  const encoding = matchKeyWithEncoding?.[6];
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
//# sourceMappingURL=index.module.js.map
