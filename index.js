const { secretbox, hash, randomBytes } = require('tweetnacl')
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = require('tweetnacl-util')
const { pbkdf2, createSHA512 } = require('hash-wasm')

const NO_PASSWORD = 'A password is required for encryption or decryption.'
const COULD_NOT_DECRYPT = 'Could not decrypt!'

const SALT_LENGTH = 24
const KEY_LENGTH = 32
const ITERATIONS = 1e4

module.exports = class Crypt {
  static async deriveKey (password, salt, opts = {}) {
    const iterations = opts.iterations || ITERATIONS
    if (!salt) { salt = randomBytes(SALT_LENGTH) }
    const key = await pbkdf2({
      password,
      salt,
      iterations,
      hashLength: KEY_LENGTH,
      hashFunction: createSHA512(),
      outputType: 'binary'
    })
    return { key, salt }
  }

  static async import (password, importString) {
    const fullMessage = decodeBase64(importString)
    const tempSalt = fullMessage.slice(0, SALT_LENGTH)
    const exportBytes = fullMessage.slice(SALT_LENGTH)
    const exportEncrypted = encodeUTF8(exportBytes)
    const tempCrypt = new Crypt(password, tempSalt)
    const exportString = await tempCrypt.decrypt(exportEncrypted)
    const [saltString, opts] = JSON.parse(exportString)
    const salt = decodeBase64(saltString)
    return new Crypt(password, salt, opts)
  }

  constructor (password, salt, opts = {}) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._raw_pass = password
    this._pass = hash(decodeUTF8(password)).slice(0, KEY_LENGTH)
    this._opts = { iterations: opts.iterations || ITERATIONS }
    this._setup = Crypt.deriveKey(this._pass, salt, this._opts)
      .then(({ key, salt: newSalt }) => {
        this._key = key
        this._salt = salt || newSalt
      })
  }

  async export () {
    await this._setup
    const tempCrypt = new Crypt(this._raw_pass)
    await tempCrypt._setup
    const saltString = encodeBase64(this._salt)
    const exportString = JSON.stringify([saltString, this._opts])
    const exportEncrypted = await tempCrypt.encrypt(exportString)
    const exportBytes = decodeUTF8(exportEncrypted)
    const fullMessage = new Uint8Array(tempCrypt._salt.length + exportBytes.length)
    fullMessage.set(tempCrypt._salt)
    fullMessage.set(exportBytes, tempCrypt._salt.length)
    return encodeBase64(fullMessage)
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
