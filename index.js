const { secretbox, hash, randomBytes } = require('tweetnacl')
const { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } = require('tweetnacl-util')
const { pbkdf2 } = require('pbkdf2')

const NO_PASSWORD = 'A password is required for encryption or decryption.'
const COULD_NOT_DECRYPT = 'Could not decrypt!'

const SALT_LENGTH = secretbox.nonceLength
const KEY_LENGTH = secretbox.keyLength
const ITERATIONS = 1e3
const HASH = 'sha512'

module.exports = class Crypt {
  static async deriveKey (password, salt) {
    if (!salt) { salt = randomBytes(SALT_LENGTH) }
    const key = await new Promise((resolve, reject) => {
      pbkdf2(password, salt, ITERATIONS, KEY_LENGTH, HASH, (err, key) => {
        /* istanbul ignore next */
        if (err) { return reject(err) } else { return resolve(key) }
      })
    })
    return { key, salt }
  }

  constructor (password, salt) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._pass = hash(decodeUTF8(password)).slice(KEY_LENGTH)
    this._setup = Crypt.deriveKey(this._pass, salt).then(async ({ key, salt: newSalt }) => {
      this._key = key
      this._salt = salt || newSalt
    })
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
