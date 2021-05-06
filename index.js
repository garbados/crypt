const tweetnacl = require('tweetnacl')
const { encodeBase64, decodeBase64 } = require('tweetnacl-util')

/* CONSTANTS */

const NO_PASSWORD = 'A password is required for encryption or decryption.'
const COULD_NOT_DECRYPT = 'Could not decrypt!'

const IV_LENGTH = 16
const SALT_LENGTH = 16
const ITERATIONS = 1e4

/* UTILS */

// string -> buffer
function encodeUTF8 (string) {
  return new TextEncoder('utf8').encode(string)
}

// buffer -> string
function decodeUTF8 (buffer) {
  return new TextDecoder('utf8').decode(buffer)
}

/* BOOTSTRAP CROSS-PLATFORM CRYPTO */

let crypto, browserCrypto
try {
  browserCrypto = window && window.crypto
} catch { /* so what? */ }
if (browserCrypto) {
  const { subtle, getRandomValues } = browserCrypto
  const KEY_LENGTH = 256
  const KEY_ALGO = 'AES-GCM'
  const HASH_ALGO = 'SHA-256'
  const PASS_ALGO = 'PBKDF2'
  const DECRYPT_FAIL = ''
  async function randomBytes (n) {
    const buf = new Uint8Array(n)
    return getRandomValues.call(browserCrypto, buf)
  }
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
    getKeyFromPassword: async function (password) {
      return subtle.importKey(
        'raw',
        encodeUTF8(password),
        PASS_ALGO,
        (PASS_ALGO !== 'PBKDF2'),
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
        // TODO use constant-time comparison method
        if (error.message === DECRYPT_FAIL) {
          throw new Error(COULD_NOT_DECRYPT)
        } else {
          throw error
        }
      }
    }
  }
} else {
  const { hash, secretbox, randomBytes } = tweetnacl
  crypto = {
    getKeyFromPassword: async function (password) {
      return hash(encodeUTF8(password)).slice(0, secretbox.keyLength)
    },
    encrypt: async function (key, plaintext) {
      const nonce = randomBytes(secretbox.nonceLength)
      const messageUint8 = encodeUTF8(plaintext)
      const box = secretbox(messageUint8, nonce, key)
      const fullMessage = new Uint8Array(nonce.length + box.length)
      fullMessage.set(nonce)
      fullMessage.set(box, nonce.length)
      return fullMessage
    },
    decrypt: async function (key, fullMessage) {
      const nonce = fullMessage.slice(0, secretbox.nonceLength)
      const message = fullMessage.slice(secretbox.nonceLength)
      const decrypted = secretbox.open(message, nonce, key)
      if (!decrypted) {
        throw new Error(COULD_NOT_DECRYPT)
      } else {
        return decrypted
      }
    }
  }
}

/* AND FINALLY, THE CRYPT ITSELF: */

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
