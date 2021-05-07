# garbados-crypt

[![CI](https://github.com/garbados/crypt/actions/workflows/ci.yaml/badge.svg)](https://github.com/garbados/crypt/actions/workflows/ci.yaml)
[![Coverage Status](https://coveralls.io/repos/github/garbados/crypt/badge.svg?branch=master)](https://coveralls.io/github/garbados/crypt?branch=master)
[![Stability](https://img.shields.io/badge/stability-stable-green.svg?style=flat-square)](https://nodejs.org/api/documentation.html#documentation_stability_index)
[![NPM Version](https://img.shields.io/npm/v/garbados-crypt.svg?style=flat-square)](https://www.npmjs.com/package/garbados-crypt)
[![JS Standard Style](https://img.shields.io/badge/code%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/feross/standard)

[garbados]: https://garbados.github.io/my-blog/
[browserify]: https://www.npmjs.com/package/browserify
[webpack]: https://www.npmjs.com/package/webpack
[npm]: https://www.npmjs.com/

Easy password-based encryption, by [garbados][garbados].

This library attempts to reflect [informed opinions](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html) while respecting realities like resource constraints, tech debt, and so on. The idea is to provide some very simple methods that just do the hard thing for you.

For example:

```javascript
const Crypt = require('garbados-crypt')

const crypt = new Crypt(password)
const encrypted = await crypt.encrypt('hello world')
console.log(encrypted)
> "O/z1zXHQ+..."
const decrypted = await crypt.decrypt(encrypted)
console.log(decrypted)
> "hello world"
```

Crypt only works with plaintext, so remember to use `JSON.stringify()` on objects before encryption and `JSON.parse()` after decryption. For classes and the like, you'll need to choose your own encoding / decoding approach.

Crypt works in the browser, too! You can require it like this:

```html
<script src="https://raw.githubusercontent.com/garbados/crypt/master/bundle.min.js" charset="utf-8"></script>
<script type="text/javascript">
// now you can encrypt in the browser! 3.7kb!
const crypt = new Crypt('a very good password')
</script>
```

You can also require it with [browserify][browserify] or [webpack][webpack], of course, but there are some [caveats](#also-how-to-bundle-crypt) to doing so.

## Install

Use [npm][npm] or whatever.

```bash
$ npm i -S garbados-crypt
```

## Usage

First, require the library. Then get to encrypting!

```javascript
const Crypt = require('garbados-crypt')

const crypt = new Crypt(password)
```

### new Crypt(password)

- `password`: A string. Make sure it's good! Or not.

### async crypt.encrypt(plaintext) => ciphertext

- `plaintext`: A string.
- `ciphertext`: A different, encrypted string.

### async crypt.decrypt(ciphertext) => plaintext

- `ciphertext`: An encrypted string produced by `crypt.encrypt()`.
- `plaintext`: The decrypted message as a string.

If decryption fails, for example because your password is incorrect, an error will be thrown.

## Also: How To Securely Store A Password

For a password-based encryption system, it makes sense to have a good reference on how to store passwords in a database. To this effect I have written [this gist](https://gist.github.com/garbados/29ca945d5964ef85e7936804c23edb9d#file-how_to_store_passwords-js) to demonstrate safe password obfuscation and verification. If you have any issue with the advice offered there, leave a comment!

## Also: How To Bundle Crypt

You probably use [browserify][browserify] or [webpack][webpack] to bundle your project together, by walking all your dependencies and transpiling them for browser environments. Some dependencies, like NodeJS [Crypto](https://nodejs.org/api/crypto.html), are replaced by complex shims like [crypto-browserify](https://github.com/crypto-browserify/crypto-browserify/) that aren't needed in [modern browsers](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto). These shims weigh in at more than half a meg when uncompressed, which renders Crypt a very heavy library for use in the browser -- especially when all those shims are never run in the browser!

To prevent your bundler from bundling crypto-browserify, you'll have to modify its invocation. For browserify, you can use the `-x crypto` option to tell browserify not to process any `require('crypto')` calls, since we can safely assume they will only be run in a non-browser environment.

```bash
$ browserify -x crypto index.js -o bundle.js
```

In webpack, use the [externals](https://webpack.js.org/configuration/externals/) configuration option to achieve the same effect:

```javascript
// webpack.config.js
module.exports = {
  //...
  externals: {
    crypto: 'crypto',
  },
}
```

In the end, Crypt weighs in at around 3.7kb -- not bad for native crypto!

## Development

First, get the source:

```bash
$ git clone git@github.com:garbados/crypt.git garbados-crypt
$ cd garbados-crypt
$ npm i
```

Use the test suite:

```bash
$ npm test
```

The test suite includes a small benchmarking test, which runs on the server and in the browser, in case you're curious about performance.

To see test coverage:

```bash
$ npm run cov
```
## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
