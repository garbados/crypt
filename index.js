const nodeCrypto = require('crypto')
const { promisify } = require('util')
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
  browserCrypto = (window && window.crypto) || nodeCrypto.webcrypto
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
  const KEY_LENGTH = 32
  const KEY_ALGO = 'AES-256-GCM'
  const HASH_ALGO = 'sha256'
  const TAG_SIZE = 16
  const DECRYPT_FAIL = Buffer.from('Unsupported state or unable to authenticate data')
  const randomBytes = promisify(nodeCrypto.randomBytes)
  const pbkdf2 = promisify(nodeCrypto.pbkdf2)
  crypto = {
    getKeyFromPassword: async function (password) {
      const buf = Buffer.from(password)
      // return deriveKey function
      return async (salt) => {
        return pbkdf2(buf, salt, ITERATIONS, KEY_LENGTH, HASH_ALGO)
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
      const ciphertext = buffer.slice(IV_LENGTH + SALT_LENGTH, buffer.length - TAG_SIZE)
      const tag = buffer.slice(buffer.length - TAG_SIZE)
      const derivedKey = await deriveKey(salt)
      try {
        const cipher = nodeCrypto.createDecipheriv(KEY_ALGO, derivedKey, iv)
        cipher.setAuthTag(tag)
        return Buffer.concat([
          cipher.update(ciphertext),
          cipher.final()
        ])
      } catch (error) {
        const buf = Buffer.from(error.message)
        if (nodeCrypto.timingSafeEqual(buf, DECRYPT_FAIL)) {
          throw new Error(COULD_NOT_DECRYPT)
        } else {
          throw error
        }
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
    try {
      const encodedPlaintext = await crypto.decrypt(this._key, buffer)
      return decodeUTF8(encodedPlaintext)
    } catch (error) {
      if (error.message === 'Cipher job failed') {
        throw new Error(COULD_NOT_DECRYPT)
      } else {
        throw error
      }
    }
  }
}
