const test = require('ava')
const crypto = require('crypto')

const { diffieHellman } = require('crypto')

let jose
let errors

test.before(async t => {
  jose = require('jose')
  errors = jose.errors
  await require('../lib')
})

test('all oct key JWE functionality', t => {
  t.plan(30)
  const key = jose.JWK.generateSync('oct', 256, { use: 'enc' })
  const key2 = jose.JWK.generateSync('oct', 256, { use: 'enc' })

  key.algorithms('encrypt').forEach((enc) => {
    if (enc.includes('C20P')) {
      jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg: 'dir', enc }), key)
      t.throws(() => {
        jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg: 'dir', enc }), key2)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      t.throws(() => {
        const jwe = jose.JWE.encrypt.flattened('foo', key, { alg: 'dir', enc })
        jwe.tag = crypto.randomBytes(11).toString('hex')
        jose.JWE.decrypt(jwe, key)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      t.throws(() => {
        const jwe = jose.JWE.encrypt.flattened('foo', key, { alg: 'dir', enc })
        jwe.iv = crypto.randomBytes(jwe.iv.length / 2).toString('hex')
        jose.JWE.decrypt(jwe, key)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
    }

    key.algorithms('wrapKey').forEach((alg) => {
      if (alg.includes('C20P' || enc.includes('C20P'))) {
        jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg, enc }), key)
        t.throws(() => {
          jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg, enc }), key2)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
        t.throws(() => {
          const jwe = jose.JWE.encrypt.flattened('foo', key, { alg, enc })
          jwe.tag = crypto.randomBytes(11).toString('hex')
          jose.JWE.decrypt(jwe, key)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
        t.throws(() => {
          const jwe = jose.JWE.encrypt.flattened('foo', key, { alg, enc })
          jwe.iv = crypto.randomBytes(jwe.iv.length / 2).toString('hex')
          jose.JWE.decrypt(jwe, key)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      }
    })
  })
})

;['P-256', 'P-384', 'P-521'].forEach((crv) => {
  test(`all EC ${crv} key JWE functionality`, t => {
    t.plan(6)
    const key = jose.JWK.generateSync('EC', crv, { use: 'enc' })
    const key2 = jose.JWK.generateSync('EC', crv, { use: 'enc' })

    key.algorithms('deriveKey').forEach((alg) => {
      if (!alg.includes('C20P')) {
        return
      }
      jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key)
      t.throws(() => {
        jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key2)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      t.throws(() => {
        const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
        jwe.tag = crypto.randomBytes(11).toString('hex')
        jose.JWE.decrypt(jwe, key)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      t.throws(() => {
        const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
        jwe.iv = crypto.randomBytes(jwe.iv.length / 2).toString('hex')
        jose.JWE.decrypt(jwe, key)
      }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
    })
  })
})

;['X25519', 'X448'].forEach((crv) => {
  if (diffieHellman && !('electron' in process.versions)) {
    test(`all OKP ${crv} key JWE functionality`, t => {
      t.plan(6)
      const key = jose.JWK.generateSync('OKP', crv, { use: 'enc' })
      const key2 = jose.JWK.generateSync('OKP', crv, { use: 'enc' })

      key.algorithms('deriveKey').forEach((alg) => {
        if (!alg.includes('C20P')) {
          return
        }
        jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key)
        t.throws(() => {
          jose.JWE.decrypt(jose.JWE.encrypt('foo', key, { alg }), key2)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
        t.throws(() => {
          const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
          jwe.tag = crypto.randomBytes(11).toString('hex')
          jose.JWE.decrypt(jwe, key)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
        t.throws(() => {
          const jwe = jose.JWE.encrypt.flattened('foo', key, { alg })
          jwe.iv = crypto.randomBytes(jwe.iv.length / 2).toString('hex')
          jose.JWE.decrypt(jwe, key)
        }, { instanceOf: errors.JWEDecryptionFailed, code: 'ERR_JWE_DECRYPTION_FAILED' })
      })
    })
  } else if (!('electron' in process.versions)) {
    test(`OKP ${crv} not supported in this Node.js runtime`, t => {
      const key = jose.JWK.generateSync('OKP', crv, { use: 'enc' })
      t.deepEqual(key.algorithms('deriveKey'), new Set())
    })
  }
})
