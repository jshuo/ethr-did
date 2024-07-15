import { Resolvable, Resolver } from 'did-resolver'
import { Contract, ContractFactory } from '@ethersproject/contracts'
import { JsonRpcProvider } from '@ethersproject/providers'
import { getResolver, EthereumDIDRegistry } from 'ethr-did-resolver'
import { DelegateTypes, EthrDID, KeyPair } from '../index'
import { createProvider, sleep } from './testUtils'
import { verifyJWT } from 'did-jwt'
import { arrayify } from '@ethersproject/bytes'
import { SigningKey } from '@ethersproject/signing-key'
import {
  Signer as JWTSigner,
} from 'did-jwt'

jest.setTimeout(30000)

describe('EthrDID', () => {
  let ethrDid: EthrDID,
    plainDid: EthrDID,
    registry: string,
    accounts: string[],
    did: string,
    identity: string,
    owner: string,
    delegate1: string,
    delegate2: string,
    resolver: Resolvable,
    signer:JWTSigner

  const provider: JsonRpcProvider = createProvider()

  beforeAll(async () => {
    const factory = ContractFactory.fromSolidity(EthereumDIDRegistry).connect(provider.getSigner(0))

    let registryContract: Contract
    registryContract = await factory.deploy()
    registryContract = await registryContract.deployed()

    await registryContract.deployTransaction.wait()

    registry = registryContract.address

    accounts = await provider.listAccounts()

    identity = accounts[1]
    owner = accounts[2]
    delegate1 = accounts[3]
    delegate2 = accounts[4]
    did = `did:ethr:dev:${identity}`

    resolver = new Resolver(getResolver({ name: 'dev', provider, registry, chainId: 1337 }))
    ethrDid = new EthrDID({
      provider,
      registry,
      identifier: identity,
      chainNameOrId: 'dev',
      signer
    })
  })

  describe('presets', () => {
    it('sets address', () => {
      expect(ethrDid.address).toEqual(identity)
    })

    it('sets did', () => {
      expect(ethrDid.did).toEqual(did)
    })
  })

  it('defaults owner to itself', () => {
    return expect(ethrDid.lookupOwner()).resolves.toEqual(identity)
  })

  describe('key management', () => {
    describe('owner changed', () => {
      beforeAll(async () => {
        await ethrDid.changeOwner(owner)
      })

      it('changes owner', () => {
        return expect(ethrDid.lookupOwner()).resolves.toEqual(owner)
      })

      it('resolves document', async () => {
        return expect((await resolver.resolve(did)).didDocument).toEqual({
          '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
          id: did,
          verificationMethod: [
            {
              id: `${did}#controller`,
              type: 'EcdsaSecp256k1RecoveryMethod2020',
              controller: did,
              blockchainAccountId: `eip155:1337:${owner}`,
            },
          ],
          authentication: [`${did}#controller`],
          assertionMethod: [`${did}#controller`],
        })
      })
    })

    describe('delegates', () => {
      describe('add signing delegate', () => {
        beforeAll(async () => {
          const txHash = await ethrDid.addDelegate(delegate1, {
            expiresIn: 86400,
          })
          await provider.waitForTransaction(txHash)
        })

        it('resolves document', async () => {
          const resolution = await resolver.resolve(did)
          return expect(resolution.didDocument).toEqual({
            '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
            id: did,
            verificationMethod: [
              {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${owner}`,
              },
              {
                id: `${did}#delegate-1`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate1}`,
              },
            ],
            authentication: [`${did}#controller`],
            assertionMethod: [`${did}#controller`, `${did}#delegate-1`],
          })
        })
      })

      describe('add auth delegate', () => {
        beforeAll(async () => {
          const txHash = await ethrDid.addDelegate(delegate2, {
            delegateType: DelegateTypes.sigAuth,
            expiresIn: 2,
          })
          await provider.waitForTransaction(txHash)
        })

        it('resolves document', async () => {
          return expect((await resolver.resolve(did)).didDocument).toEqual({
            '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
            id: did,
            verificationMethod: [
              {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${owner}`,
              },
              {
                id: `${did}#delegate-1`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate1}`,
              },
              {
                id: `${did}#delegate-2`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate2}`,
              },
            ],
            authentication: [`${did}#controller`, `${did}#delegate-2`],
            assertionMethod: [`${did}#controller`, `${did}#delegate-1`, `${did}#delegate-2`],
          })
        })
      })

      describe('expire automatically', () => {
        beforeAll(async () => {
          await sleep(5)
        })

        it('resolves document', async () => {
          const resolution = await resolver.resolve(did)
          return expect(resolution.didDocument).toEqual({
            '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
            id: did,
            verificationMethod: [
              {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${owner}`,
              },
              {
                id: `${did}#delegate-1`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate1}`,
              },
            ],
            authentication: [`${did}#controller`],
            assertionMethod: [`${did}#controller`, `${did}#delegate-1`],
          })
        })
      })

      describe('re-add auth delegate', () => {
        beforeAll(async () => {
          const txHash = await ethrDid.addDelegate(delegate2, {
            delegateType: DelegateTypes.sigAuth,
          })
          await provider.waitForTransaction(txHash)
        })

        it('resolves document', async () => {
          return expect((await resolver.resolve(did)).didDocument).toEqual({
            '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
            id: did,
            verificationMethod: [
              {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${owner}`,
              },
              {
                id: `${did}#delegate-1`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate1}`,
              },
              {
                id: `${did}#delegate-3`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate2}`,
              },
            ],
            authentication: [`${did}#controller`, `${did}#delegate-3`],
            assertionMethod: [`${did}#controller`, `${did}#delegate-1`, `${did}#delegate-3`],
          })
        })
      })

      describe('revokes delegate', () => {
        it('resolves document', async () => {
          const txHash = await ethrDid.revokeDelegate(delegate2, DelegateTypes.sigAuth)
          await provider.waitForTransaction(txHash)
          await sleep(2) // this smells but for some reason ganache is not updating :(

          const resolution = await resolver.resolve(did)
          return expect(resolution.didDocument).toEqual({
            '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
            id: did,
            verificationMethod: [
              {
                id: `${did}#controller`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${owner}`,
              },
              {
                id: `${did}#delegate-1`,
                type: 'EcdsaSecp256k1RecoveryMethod2020',
                controller: did,
                blockchainAccountId: `eip155:1337:${delegate1}`,
              },
            ],
            authentication: [`${did}#controller`],
            assertionMethod: [`${did}#controller`, `${did}#delegate-1`],
          })
        })
      })
    })

    describe('attributes', () => {
      describe('publicKey', () => {
        describe('Secp256k1VerificationKey2018', () => {
          beforeAll(async () => {
            const txHash = await ethrDid.setAttribute(
              'did/pub/Secp256k1/veriKey',
              '0x02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
              86400
            )
            await provider.waitForTransaction(txHash)
          })

          it('resolves document', async () => {
            return expect((await resolver.resolve(did)).didDocument).toEqual({
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
              ],
              id: did,
              verificationMethod: [
                {
                  id: `${did}#controller`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${owner}`,
                },
                {
                  id: `${did}#delegate-1`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${delegate1}`,
                },
                {
                  id: `${did}#delegate-5`,
                  type: 'EcdsaSecp256k1VerificationKey2019',
                  controller: did,
                  publicKeyHex: '02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
                },
              ],
              authentication: [`${did}#controller`],
              assertionMethod: [`${did}#controller`, `${did}#delegate-1`, `${did}#delegate-5`],
            })
          })
        })

        describe('Base64 Encoded Key', () => {
          beforeAll(async () => {
            const txHash = await ethrDid.setAttribute(
              'did/pub/Ed25519/veriKey/base64',
              'Arl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2tx',
              86400
            )
            await provider.waitForTransaction(txHash)
          })

          it('resolves document', async () => {
            return expect((await resolver.resolve(did)).didDocument).toEqual({
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
              ],
              id: did,
              verificationMethod: [
                {
                  id: `${did}#controller`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${owner}`,
                },
                {
                  id: `${did}#delegate-1`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${delegate1}`,
                },
                {
                  id: `${did}#delegate-5`,
                  type: 'EcdsaSecp256k1VerificationKey2019',
                  controller: did,
                  publicKeyHex: '02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
                },
                {
                  id: `${did}#delegate-6`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: 'Arl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2tx',
                },
              ],
              authentication: [`${did}#controller`],
              assertionMethod: [`${did}#controller`, `${did}#delegate-1`, `${did}#delegate-5`, `${did}#delegate-6`],
            })
          })
        })

        describe('Use Buffer', () => {
          beforeAll(async () => {
            const txHash = await ethrDid.setAttribute(
              'did/pub/Ed25519/veriKey/base64',
              Buffer.from('f2b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b72', 'hex'),
              86400
            )
            await provider.waitForTransaction(txHash)
          })

          it('resolves document', async () => {
            return expect((await resolver.resolve(did)).didDocument).toEqual({
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
              ],
              id: did,
              verificationMethod: [
                {
                  id: `${did}#controller`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${owner}`,
                },
                {
                  id: `${did}#delegate-1`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${delegate1}`,
                },
                {
                  id: `${did}#delegate-5`,
                  type: 'EcdsaSecp256k1VerificationKey2019',
                  controller: did,
                  publicKeyHex: '02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
                },
                {
                  id: `${did}#delegate-6`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: 'Arl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2tx',
                },
                {
                  id: `${did}#delegate-7`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: '8rl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2ty',
                },
              ],
              authentication: [`${did}#controller`],
              assertionMethod: [
                `${did}#controller`,
                `${did}#delegate-1`,
                `${did}#delegate-5`,
                `${did}#delegate-6`,
                `${did}#delegate-7`,
              ],
            })
          })
        })
      })

      describe('service endpoints', () => {
        describe('HubService', () => {
          beforeAll(async () => {
            const txHash = await ethrDid.setAttribute('did/svc/HubService', 'https://hubs.uport.me', 86400)
            await provider.waitForTransaction(txHash)
          })
          it('resolves document', async () => {
            return expect((await resolver.resolve(did)).didDocument).toEqual({
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
              ],
              id: did,
              verificationMethod: [
                {
                  id: `${did}#controller`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${owner}`,
                },
                {
                  id: `${did}#delegate-1`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${delegate1}`,
                },
                {
                  id: `${did}#delegate-5`,
                  type: 'EcdsaSecp256k1VerificationKey2019',
                  controller: did,
                  publicKeyHex: '02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
                },
                {
                  id: `${did}#delegate-6`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: 'Arl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2tx',
                },
                {
                  id: `${did}#delegate-7`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: '8rl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2ty',
                },
              ],
              authentication: [`${did}#controller`],
              assertionMethod: [
                `${did}#controller`,
                `${did}#delegate-1`,
                `${did}#delegate-5`,
                `${did}#delegate-6`,
                `${did}#delegate-7`,
              ],
              service: [
                {
                  id: 'did:ethr:dev:0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf#service-1',
                  type: 'HubService',
                  serviceEndpoint: 'https://hubs.uport.me',
                },
              ],
            })
          })
        })

        describe('revoke HubService', () => {
          beforeAll(async () => {
            const txHash = await ethrDid.revokeAttribute('did/svc/HubService', 'https://hubs.uport.me')
            await provider.waitForTransaction(txHash)
          })
          it('resolves document', async () => {
            return expect((await resolver.resolve(did)).didDocument).toEqual({
              '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
              ],
              id: did,
              verificationMethod: [
                {
                  id: `${did}#controller`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${owner}`,
                },
                {
                  id: `${did}#delegate-1`,
                  type: 'EcdsaSecp256k1RecoveryMethod2020',
                  controller: did,
                  blockchainAccountId: `eip155:1337:${delegate1}`,
                },
                {
                  id: `${did}#delegate-5`,
                  type: 'EcdsaSecp256k1VerificationKey2019',
                  controller: did,
                  publicKeyHex: '02b97c30de767f084ce3080168ee293053ba33b235d7116a3263d29f1450936b71',
                },
                {
                  id: `${did}#delegate-6`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: 'Arl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2tx',
                },
                {
                  id: `${did}#delegate-7`,
                  type: 'Ed25519VerificationKey2018',
                  controller: did,
                  publicKeyBase64: '8rl8MN52fwhM4wgBaO4pMFO6M7I11xFqMmPSnxRQk2ty',
                },
              ],
              authentication: [`${did}#controller`],
              assertionMethod: [
                `${did}#controller`,
                `${did}#delegate-1`,
                `${did}#delegate-5`,
                `${did}#delegate-6`,
                `${did}#delegate-7`,
              ],
            })
          })
        })
      })
    })
  })

  describe('signJWT', () => {
    describe('No signer configured', () => {
      it('should fail', () => {
        return expect(ethrDid.signJWT({ hello: 'world' })).rejects.toEqual(new Error('No signer configured'))
      })
    })

    describe('creating a signing Delegate', () => {
      let kp: any;
      beforeAll(async () => {
        kp = await ethrDid.createSigningDelegate()
      })

      it('should sign valid jwt', async () => {
        const jwt = await ethrDid.signJWT({ hello: 'world' })
        const verification = await verifyJWT(jwt, { resolver })
        const { signer } = verification
        expect(signer).toEqual({
          id: `${did}#delegate-8`,
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: did,
          blockchainAccountId: `eip155:1337:${kp.address}`,
        })
      })
    })

  })



})

