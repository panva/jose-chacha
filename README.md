# jose-chacha

This is a plugin for the [`jose`][jose] (v2.x) package that implements the following Individual Draft

> ChaCha derived AEAD algorithms in JSON Object Signing and Encryption (JOSE)  
> source: https://tools.ietf.org/html/draft-amringer-jose-chacha-01

The following new algorithms are available

- `C20P` content encryption algorithm
- `XC20P` content encryption algorithm
- `C20PKW` content encryption key wrapping algorithm
- `XC20PKW` content encryption key wrapping algorithm
- `ECDH-ES+C20PKW` Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static
- `ECDH-ES+XC20PKW` Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static

## Why a plugin?

1) The draft is an individual draft, breaking changes or lacking adoption may occur, hence its not
something desired to be part of jose core package.
2) `AEAD_XCHACHA20_POLY1305` is not available in OpenSSL bundled with Node.js yet, in the plugin
this cipher is handled via libsodium.

## Usage

Installing

```console
npm install jose // jose ^1.16.0 || ^2.0.1 declared as a peer dependency
npm install jose-chacha
```

```js
const jose = require('jose')
const chacha = require('jose-chacha')

;(async () => {
  await chacha // wait for libsodium to be ready!

  {
    const key = jose.JWK.generateSync('oct', 256)
    console.log(key.algorithms())
    console.log(jose.JWE.encrypt('foobar', key, { alg: 'dir', enc: 'XC20P' }))
  }

  {
    const key = jose.JWK.generateSync('EC', 'P-256')
    console.log(key.algorithms())
    console.log(jose.JWE.encrypt('foobar', key, { alg: 'ECDH-ES+XC20PKW', enc: 'XC20P' }))
  }
})()
```

**Note:** This plugin only supports Node.js runtime >= 12.0.0 and Electron >= 6.0.0

Have a question about using `jose`? - [ask][ask].  
Found a bug? - [report it][bug].  
Missing a feature? - If it wasn't already discussed before, [ask for it][suggest-feature].  
Found a vulnerability? - Reach out to us via email first, see [security vulnerability disclosure][security-vulnerability].

## Support

If you or your business use `jose`, please consider becoming a [sponsor][support-sponsor] so I can continue maintaining it and adding new features carefree.

[ask]: https://github.com/panva/jose-chacha/issues/new?labels=question&template=question.md&title=question%3A+
[bug]: https://github.com/panva/jose-chacha/issues/new?labels=bug&template=bug-report.md&title=bug%3A+
[suggest-feature]: https://github.com/panva/jose-chacha/issues/new?labels=enhancement&template=feature-request.md&title=proposal%3A+
[security-vulnerability]: https://github.com/panva/jose-chacha/issues/new?template=security-vulnerability.md
[support-sponsor]: https://github.com/sponsors/panva
[jose]: https://github.com/panva/jose
