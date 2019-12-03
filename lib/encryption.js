module.exports = (registry, cipherName, alg, ivLength) => {
  const { createCipheriv, createDecipheriv } = require('crypto')
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
    const key = asInput(keyObject, false)
    checkInput(iv)

    const cipher = createCipheriv(cipherName, key, iv, { authTagLength: 16 })
    cipher.setAAD(aad)

    const ciphertext = Buffer.concat([cipher.update(cleartext), cipher.final()])
    const tag = cipher.getAuthTag()

    return { ciphertext, tag }
  }

  const decrypt = ({ [KEYOBJECT]: keyObject }, ciphertext, { iv, tag = Buffer.alloc(0), aad = Buffer.alloc(0) }) => {
    const key = asInput(keyObject, false)
    checkInput(iv, tag)

    try {
      const cipher = createDecipheriv(cipherName, key, iv, { authTagLength: 16 })
      cipher.setAuthTag(tag)
      cipher.setAAD(aad)

      return Buffer.concat([cipher.update(ciphertext), cipher.final()])
    } catch (err) {
      throw new JWEDecryptionFailed()
    }
  }

  registry.JWA.encrypt.set(alg, encrypt)
  registry.JWA.decrypt.set(alg, decrypt)
  registry.JWK.oct.encrypt[alg] = registry.JWK.oct.decrypt[alg] = key => (key.use === 'enc' || key.use === undefined) && key.length === 256
}
