const { encodeBase64, decodeBase64 } = require('tweetnacl-util')

/* CONSTANTS */

const COULD_NOT_DECRYPT = 'Could not decrypt!'
const NO_PASSWORD = 'A password is required for encryption or decryption.'

const ITERATIONS = 1e4
const IV_LENGTH = 16
const SALT_LENGTH = 16

/* UTILS */

// string -> buffer
function encodeUTF8 (string) {
  return new TextEncoder('utf8').encode(string)
}

// buffer -> string
function decodeUTF8 (buffer) {
  return new TextDecoder('utf8').decode(buffer)
}

// convenient promise -> callback
function cbify (resolve, reject) {
  return (err, result) => {
    if (err) { reject(err) } else { resolve(result) }
  }
}

// check an error message against failure messages
// to determine if a decryption failure occurred
function checkDecrypt (error, ...failMessages) {
  if (failMessages.includes(error.message)) {
    throw new Error(COULD_NOT_DECRYPT)
  } else {
    throw error
  }
}

/* BOOTSTRAP CRYPTO PRIMITIVES */

let crypto, browserCrypto
// check window, if you're in a browser
try { browserCrypto = (window && window.crypto) } catch {}
// check for global, if we're in a web worker
if (!browserCrypto) try { browserCrypto = (global && global.crypto) } catch {}
// lastly try using node crypto
if (!browserCrypto) { browserCrypto = require('crypto').webcrypto }
if (browserCrypto) {
  // finally, parse it for the basics we require
  const { subtle, getRandomValues } = browserCrypto

  // browser-specific constants
  const HASH_ALGO = 'SHA-256'
  const KEY_ALGO = 'AES-GCM'
  const PASS_ALGO = 'PBKDF2'
  const KEY_LENGTH = 256
  const DECRYPT_FAIL = 'Cipher job failed'

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

  crypto = {
    // derive an intermediate key from a password
    getKeyFromPassword: async function (password) {
      return subtle.importKey(
        'raw',
        encodeUTF8(password),
        PASS_ALGO,
        false,
        ['deriveKey'])
    },
    // given a key and plaintext, return an encrypted buffer
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
    // given a key and an encrypted buffer, return plaintext
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
        checkDecrypt(error, DECRYPT_FAIL, '')
      }
    }
  }
} else {
  // fallback to node not-web crypto
  const nodeCrypto = require('crypto')

  // node-specific constants
  const HASH_ALGO = 'sha256'
  const KEY_ALGO = 'AES-256-GCM'
  const KEY_LENGTH = 32
  const TAG_LENGTH = 16
  const DECRYPT_FAIL = 'Unsupported state or unable to authenticate data'

  async function randomBytes (n) {
    return new Promise((resolve, reject) => {
      const cb = cbify(resolve, reject)
      nodeCrypto.randomBytes(n, cb)
    })
  }

  async function pbkdf2 (password, salt) {
    return new Promise((resolve, reject) => {
      const cb = cbify(resolve, reject)
      nodeCrypto.pbkdf2(password, salt, ITERATIONS, KEY_LENGTH, HASH_ALGO, cb)
    })
  }

  crypto = {
    getKeyFromPassword: async function (password) {
      return (salt) => {
        return pbkdf2(password, salt)
      }
    },
    encrypt: async function (deriveKey, plaintext) {
      const iv = await randomBytes(IV_LENGTH)
      const salt = await randomBytes(SALT_LENGTH)
      const derivedKey = await deriveKey(salt)
      const cipher = nodeCrypto.createCipheriv(KEY_ALGO, derivedKey, iv)
      const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final()
      ])
      const tag = cipher.getAuthTag()
      return Buffer.concat([iv, salt, ciphertext, tag])
    },
    decrypt: async function (deriveKey, buffer) {
      const iv = buffer.slice(0, IV_LENGTH)
      const salt = buffer.slice(IV_LENGTH, IV_LENGTH + SALT_LENGTH)
      const ciphertext = buffer.slice(IV_LENGTH + SALT_LENGTH, buffer.length - TAG_LENGTH)
      const tag = buffer.slice(buffer.length - TAG_LENGTH)
      const derivedKey = await deriveKey(salt)
      try {
        const cipher = nodeCrypto.createDecipheriv(KEY_ALGO, derivedKey, iv)
        cipher.setAuthTag(tag)
        return Buffer.concat([
          cipher.update(ciphertext),
          cipher.final()
        ])
      } catch (error) {
        checkDecrypt(error, DECRYPT_FAIL)
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
