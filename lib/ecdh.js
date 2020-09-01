const { diffieHellman } = require('crypto')

module.exports = (registry, alg) => {
  const { wrapKey, unwrapKey } = require('jose/lib/jwa/ecdh/kw')
  const derive = require('jose/lib/jwa/ecdh/derive')
  let secp256k1
  try {
    ({ name: secp256k1 } = require('jose/lib/jwk/key/secp256k1_crv'))
  } catch (err) {
    secp256k1 = 'secp256k1'
  }

  const kwWrap = registry.JWA.keyManagementEncrypt.get(alg.substr(8))
  const kwUnwrap = registry.JWA.keyManagementDecrypt.get(alg.substr(8))

  registry.JWA.keyManagementEncrypt.set(alg, wrapKey.bind(undefined, kwWrap, derive.bind(undefined, alg, 256)))
  registry.JWA.keyManagementDecrypt.set(alg, unwrapKey.bind(undefined, kwUnwrap, derive.bind(undefined, alg, 256)))
  registry.JWK.EC.deriveKey[alg] = key => (key.use === 'enc' || key.use === undefined) && key.crv !== secp256k1
  if (diffieHellman) {
    registry.JWK.OKP.deriveKey[alg] = key => (key.use === 'enc' || key.use === undefined) && key.keyObject.asymmetricKeyType.startsWith('x')
  }
  registry.ECDH_DERIVE_LENGTHS.set(alg, 256)
}
