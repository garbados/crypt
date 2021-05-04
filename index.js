const { subtle, getRandomValues } = require('crypto').webcrypto // for browser compat
const { encodeBase64, decodeBase64 } = require('tweetnacl-util')

const NO_PASSWORD = 'A password is required for encryption or decryption.'
const COULD_NOT_DECRYPT = 'Could not decrypt!'

const IV_LENGTH = 16
const KEY_LENGTH = 256
const SALT_LENGTH = 16
const KEY_ALGO = 'AES-GCM'
const HASH_ALGO = 'SHA-256'
const PASS_ALGO = 'PBKDF2'
const ITERATIONS = 1e4

// string -> buffer
function encodeUTF8 (string) {
  return new TextEncoder('utf8').encode(string)
}

// buffer -> string
function decodeUTF8 (buffer) {
  return new TextDecoder('utf8').decode(buffer)
}

async function getKeyFromPassword (password) {
  const encoded = encodeUTF8(password)
  return subtle.importKey('raw', encoded, {
    name: PASS_ALGO
  }, (PASS_ALGO !== 'PBKDF2'), ['deriveKey'])
}

module.exports = class Crypt {
  constructor (password, options = {}) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._pending = getKeyFromPassword(password).then((key) => {
      this._key = key
    })
  }

  async _getKey (salt) {
    await this._pending
    return subtle.deriveKey({
      name: PASS_ALGO,
      salt,
      iterations: ITERATIONS,
      hash: HASH_ALGO
    }, this._key, {
      name: KEY_ALGO,
      length: KEY_LENGTH
    }, true, ['encrypt', 'decrypt'])
  }

  async encrypt (plaintext) {
    await this._pending
    const iv = getRandomValues(new Uint8Array(IV_LENGTH))
    const salt = getRandomValues(new Uint8Array(SALT_LENGTH))
    const key = await this._getKey(salt)
    const encoded = encodeUTF8(plaintext)
    const opts = { name: KEY_ALGO, iv }
    const ciphertext = await subtle.encrypt(opts, key, encoded)
    const fullMessage = new Uint8Array(iv.length + salt.length + ciphertext.byteLength)
    fullMessage.set(iv)
    fullMessage.set(salt, iv.length)
    fullMessage.set(new Uint8Array(ciphertext), iv.length + salt.length)
    return encodeBase64(fullMessage)
  }

  async decrypt (encrypted) {
    await this._pending
    const fullMessage = decodeBase64(encrypted)
    const iv = fullMessage.slice(0, IV_LENGTH)
    const salt = fullMessage.slice(IV_LENGTH, IV_LENGTH + SALT_LENGTH)
    const ciphertext = fullMessage.slice(IV_LENGTH + SALT_LENGTH)
    const key = await this._getKey(salt)
    try {
      const encodedPlaintext = await subtle.decrypt({
        name: KEY_ALGO,
        iv
      }, key, ciphertext)
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
