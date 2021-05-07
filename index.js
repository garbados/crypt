const { encodeBase64, decodeBase64 } = require('tweetnacl-util')

/* CONSTANTS */

const COULD_NOT_DECRYPT = 'Could not decrypt!'
const DECRYPT_FAIL = 'Cipher job failed'
const NO_PASSWORD = 'A password is required for encryption or decryption.'

const HASH_ALGO = 'SHA-256'
const KEY_ALGO = 'AES-GCM'
const PASS_ALGO = 'PBKDF2'
const ITERATIONS = 1e4
const IV_LENGTH = 16
const KEY_LENGTH = 256
const SALT_LENGTH = 16

/* BOOTSTRAP CRYPTO PRIMITIVES */

let browserCrypto
// check window, if you're in a browser
try { browserCrypto = (window && window.crypto) } catch { /* so what? */ }
// check for global, if we're in a web worker
if (!browserCrypto) try { browserCrypto = (global && global.crypto) } catch { /* so what? */ }
// lastly try using node crypto
if (!browserCrypto) { browserCrypto = require('crypto').webcrypto }
// finally, parse it for the basics we require
const { subtle, getRandomValues } = browserCrypto

/* UTILS */

// string -> buffer
function encodeUTF8 (string) {
  return new TextEncoder('utf8').encode(string)
}

// buffer -> string
function decodeUTF8 (buffer) {
  return new TextDecoder('utf8').decode(buffer)
}

// very random number generator
async function randomBytes (n) {
  const buf = new Uint8Array(n)
  return getRandomValues.call(browserCrypto, buf)
}

// derive op-specific key from another key and a salt
async function deriveKey (key, salt) {
  return subtle.deriveKey({
    name: PASS_ALGO,
    salt,
    iterations: ITERATIONS,
    hash: HASH_ALGO
  }, key, {
    name: KEY_ALGO,
    length: KEY_LENGTH
  }, true, ['encrypt', 'decrypt'])
}

/* OUR VERY OWN CRYPTO ABSTRACTION */

const crypto = {
  getKeyFromPassword: async function (password) {
    return subtle.importKey(
      'raw',
      encodeUTF8(password),
      PASS_ALGO,
      false,
      ['deriveKey'])
  },
  encrypt: async function (key, plaintext) {
    const iv = await randomBytes(IV_LENGTH)
    const salt = await randomBytes(SALT_LENGTH)
    const derivedKey = await deriveKey(key, salt)
    const encoded = encodeUTF8(plaintext)
    const opts = { name: KEY_ALGO, iv }
    const ciphertext = await subtle.encrypt(opts, derivedKey, encoded)
    const fullMessage = new Uint8Array(iv.length + salt.length + ciphertext.byteLength)
    fullMessage.set(iv)
    fullMessage.set(salt, iv.length)
    fullMessage.set(new Uint8Array(ciphertext), iv.length + salt.length)
    return fullMessage
  },
  decrypt: async function (key, fullMessage) {
    const iv = fullMessage.slice(0, IV_LENGTH)
    const salt = fullMessage.slice(IV_LENGTH, IV_LENGTH + SALT_LENGTH)
    const ciphertext = fullMessage.slice(IV_LENGTH + SALT_LENGTH)
    const derivedKey = await deriveKey(key, salt)
    const opts = { name: KEY_ALGO, iv }
    try {
      const plaintext = await subtle.decrypt(opts, derivedKey, ciphertext)
      return plaintext
    } catch (error) {
      // error message is empty in browser but not in node
      if (error.message === DECRYPT_FAIL || error.message === '') {
        throw new Error(COULD_NOT_DECRYPT)
      } else {
        throw error
      }
    }
  }
}

/* AND NOW, THE CRYPT! */

module.exports = class Crypt {
  constructor (password) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._pending = crypto.getKeyFromPassword(password).then((key) => {
      this._key = key
    })
  }

  async encrypt (plaintext) {
    await this._pending
    const buffer = await crypto.encrypt(this._key, plaintext)
    return encodeBase64(buffer)
  }

  async decrypt (encrypted) {
    await this._pending
    const buffer = decodeBase64(encrypted)
    const encodedPlaintext = await crypto.decrypt(this._key, buffer)
    return decodeUTF8(encodedPlaintext)
  }
}
