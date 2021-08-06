const { secretbox, hash, randomBytes } = require('tweetnacl')
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = require('tweetnacl-util')
const { argon2id, createSHA512 } = require('hash-wasm')

const NO_PASSWORD = 'A password is required for encryption or decryption.'
const COULD_NOT_DECRYPT = 'Could not decrypt!'

const KEY_LENGTH = 32

const SALT_LENGTH = 16 // size of salt in bytes; argon2 authors recommend 16 (128 bits)
const MEMORY_SIZE = 2 ** 12 // 2 ** N kilobytes; increase N to raise strength
const ITERATIONS = 1e2 // 1 and N zeroes; increase N to raise strength
const PARALLELISM = 1 // how many threads to spawn. crypt assumes a single-threaded environment.

// convenience method for combining given opts with defaults
// istanbul ignore next // for some reason
function getOpts (opts = {}) {
  return {
    saltLength: opts.saltLength || SALT_LENGTH,
    memorySize: opts.memorySize || MEMORY_SIZE,
    iterations: opts.iterations || ITERATIONS,
    parallelism: opts.parallelism || PARALLELISM
  }
}

module.exports = class Crypt {
  // derive an encryption key from given parameters
  static async deriveKey (password, salt, opts = {}) {
    // parse opts
    opts = getOpts(opts)
    const { saltLength, ...keyOpts } = opts
    // generate a random salt if one is not provided
    if (!salt) { salt = randomBytes(saltLength) }
    const key = await argon2id({
      password,
      salt,
      ...keyOpts,
      hashLength: KEY_LENGTH,
      hashFunction: createSHA512(),
      outputType: 'binary'
    })
    return { key, salt }
  }

  // create a new Crypt instance from
  static async import (password, exportString) {
    // parse exportString into its components
    const exportBytes = decodeBase64(exportString)
    const exportJson = encodeUTF8(exportBytes)
    const [saltString, opts] = JSON.parse(exportJson)
    const salt = decodeBase64(saltString)
    // return a new crypt with the imported settings
    return Crypt.new(password, salt, opts)
  }

  // async constructor which awaits setup
  static async new (...args) {
    const crypt = new Crypt(...args)
    await crypt._setup
    return crypt
  }

  constructor (password, salt, opts = {}) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._pass = hash(decodeUTF8(password))
    this._opts = getOpts(opts)
    this._setup = Crypt.deriveKey(this._pass, salt, this._opts)
      .then(({ key, salt: newSalt }) => {
        this._key = key
        this._salt = salt || newSalt
      })
  }

  async export () {
    await this._setup
    const saltString = encodeBase64(this._salt)
    const exportJson = JSON.stringify([saltString, this._opts])
    const exportBytes = decodeUTF8(exportJson)
    const exportString = encodeBase64(exportBytes)
    return exportString
  }

  async encrypt (plaintext) {
    await this._setup
    const nonce = randomBytes(secretbox.nonceLength)
    const messageUint8 = decodeUTF8(plaintext)
    const box = secretbox(messageUint8, nonce, this._key)
    const fullMessage = new Uint8Array(nonce.length + box.length)
    fullMessage.set(nonce)
    fullMessage.set(box, nonce.length)
    const base64FullMessage = encodeBase64(fullMessage)
    return base64FullMessage
  }

  async decrypt (messageWithNonce) {
    await this._setup
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce)
    const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength)
    const message = messageWithNonceAsUint8Array.slice(secretbox.nonceLength)
    const decrypted = secretbox.open(message, nonce, this._key)
    if (!decrypted) {
      throw new Error(COULD_NOT_DECRYPT)
    } else {
      return encodeUTF8(decrypted)
    }
  }
}
