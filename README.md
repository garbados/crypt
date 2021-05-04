# garbados-crypt

Easy password-based encryption, by [garbados](https://garbados.github.io/my-blog/).

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

## Install

Use [npm](https://www.npmjs.com/) or whatever.

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
- `plaintext`: The decrypted message.

If decryption fails, for example because your password is incorrect, an error will be thrown.

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

The test suite includes a small benchmarking test, in case you're curious about performance.

To see test coverage:

```bash
$ npm run cov
```

There is also a simple browser-based test that you can use to perform simple benchmarking in the browser, using [browserify](https://www.npmjs.com/package/browserify). First, start the test server:

```bash
$ npm run test:browser

...

   ┌────────────────────────────────────────────────┐
   │                                                │
   │   Serving!                                     │
   │                                                │
   │   - Local:            http://localhost:5000    │
   │   - On Your Network:  http://10.0.0.131:5000   │
   │                                                │
   │   Copied local address to clipboard!           │
   │                                                │
   └────────────────────────────────────────────────┘
```

Now you can visit [http://localhost:5000/test](http://localhost:5000/test) and open your dev console to see the results of the test:

```
10000 round-trip operations took 322ms
```

## Why TweetNaCl.js?

This library uses [tweetnacl](https://www.npmjs.com/package/tweetnacl) for encryption, rather than native crypto. You might have feelings about this.

I chose it because it's fast on NodeJS, uses top-shelf algorithms, and has undergone a [reasonable audit](https://www.npmjs.com/package/tweetnacl#audits). I'm open to PRs that use native crypto while retaining Crypt's API.

## License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
