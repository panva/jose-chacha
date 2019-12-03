module.exports = (registry, alg, ivLength, libsodium, enc, dec) => {
  const { errors: { JWEInvalid, JWEDecryptionFailed } } = require('jose')
  const { asInput } = require('jose/lib/help/key_object')
  const { KEYOBJECT } = require('jose/lib/help/consts')

  registry.KEYLENGTHS.set(alg, 256)
  registry.IVLENGTHS.set(alg, ivLength)

  const checkInput = function (iv, tag) {
    if (iv.length !== ivLength / 8) {
      throw new JWEInvalid('invalid iv')
    }
    if (arguments.length === 2) {
      if (tag.length !== 16) {
        throw new JWEInvalid('invalid tag')
      }
    }
  }

  const encrypt = ({ [KEYOBJECT]: keyObject }, cleartext, { iv, aad = Buffer.alloc(0) }) => {
    const key = Buffer.isBuffer(keyObject) ? keyObject : asInput(keyObject, false).export()
    checkInput(iv)

    const { ciphertext, mac } = libsodium[enc](cleartext, aad, undefined, iv, key)

    return { ciphertext: Buffer.from(ciphertext), tag: Buffer.from(mac) }
  }

  const decrypt = ({ [KEYOBJECT]: keyObject }, ciphertext, { iv, tag = Buffer.alloc(0), aad = Buffer.alloc(0) }) => {
    const key = Buffer.isBuffer(keyObject) ? keyObject : asInput(keyObject, false).export()
    checkInput(iv, tag)

    try {
      return Buffer.from(libsodium[dec](undefined, ciphertext, tag, aad, iv, key))
    } catch (err) {
      throw new JWEDecryptionFailed()
    }
  }

  registry.JWA.encrypt.set(alg, encrypt)
  registry.JWA.decrypt.set(alg, decrypt)
  registry.JWK.oct.encrypt[alg] = registry.JWK.oct.decrypt[alg] = key => (key.use === 'enc' || key.use === undefined) && key.length === 256
}
