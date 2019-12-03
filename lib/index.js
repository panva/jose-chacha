const { getCiphers } = require('crypto')
const { deprecate } = require('util')

const encryption = require('./encryption')
const ecdh = require('./ecdh')
const kw = require('./kw')
const fallback = require('./libsodium')

let libsodium

const plugin = (registry, alg, register) => {
  if (registry.has(alg)) {
    deprecate(() => {}, `${alg} is already registered in the jose package algorithm registry, skipping...`)()
  } else {
    register()
  }
}

module.exports = (async () => {
  const registry = require('jose/lib/registry')

  plugin(registry.JWA.encrypt, 'C20P', () => {
    const cipher = 'chacha20-poly1305'
    if (getCiphers().includes(cipher)) {
      encryption(registry, cipher, 'C20P', 96)
    } else {
      libsodium = require('libsodium-wrappers')

      fallback(
        registry,
        'C20P',
        96,
        libsodium,
        'crypto_aead_chacha20poly1305_ietf_encrypt_detached',
        'crypto_aead_chacha20poly1305_ietf_decrypt_detached'
      )
    }
  })

  plugin(registry.JWA.encrypt, 'XC20P', () => {
    const cipher = 'xchacha20-poly1305'
    if (getCiphers().includes(cipher)) {
      encryption(registry, cipher, 'XC20P', 192)
    } else {
      libsodium = libsodium || require('libsodium-wrappers')
      fallback(
        registry,
        'XC20P',
        192,
        libsodium,
        'crypto_aead_xchacha20poly1305_ietf_encrypt_detached',
        'crypto_aead_xchacha20poly1305_ietf_decrypt_detached'
      )
    }
  })

  plugin(registry.JWA.keyManagementEncrypt, 'C20PKW', kw.bind(undefined, registry, 'C20PKW', 96))
  plugin(registry.JWA.keyManagementEncrypt, 'XC20PKW', kw.bind(undefined, registry, 'XC20PKW', 192))
  plugin(registry.JWA.keyManagementEncrypt, 'ECDH-ES+C20PKW', ecdh.bind(undefined, registry, 'ECDH-ES+C20PKW'))
  plugin(registry.JWA.keyManagementEncrypt, 'ECDH-ES+XC20PKW', ecdh.bind(undefined, registry, 'ECDH-ES+XC20PKW'))

  if (libsodium) {
    return libsodium.ready.then(() => undefined)
  }

  return undefined
})()
