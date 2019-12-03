module.exports = (registry, alg, ivLength) => {
  const generateIV = require('jose/lib/help/generate_iv')
  const base64url = require('jose/lib/help/base64url')

  registry.IVLENGTHS.set(alg, ivLength)

  const encrypt = registry.JWA.encrypt.get(alg.substr(0, alg.length - 2))
  const decrypt = registry.JWA.decrypt.get(alg.substr(0, alg.length - 2))

  registry.JWA.keyManagementEncrypt.set(alg, (key, payload) => {
    const iv = generateIV(alg)
    const { ciphertext, tag } = encrypt(key, payload, { iv })
    return {
      wrapped: ciphertext,
      header: { tag: base64url.encodeBuffer(tag), iv: base64url.encodeBuffer(iv) }
    }
  })
  registry.JWA.keyManagementDecrypt.set(alg, decrypt)
  registry.JWK.oct.wrapKey[alg] = registry.JWK.oct.unwrapKey[alg] = key => (key.use === 'enc' || key.use === undefined) && key.length === 256
}
