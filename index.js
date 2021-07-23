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

  constructor (password) {
    if (!password) { throw new Error(NO_PASSWORD) }
    this._pass = hash(decodeUTF8(password)).slice(0, KEY_LENGTH)
  }

  async encrypt (plaintext) {
    const { key, salt } = await Crypt.deriveKey(this._pass)
    const nonce = randomBytes(secretbox.nonceLength)
    const messageUint8 = decodeUTF8(plaintext)
    const box = secretbox(messageUint8, nonce, key)
    const fullMessage = new Uint8Array(salt.length + nonce.length + box.length)
    fullMessage.set(salt)
    fullMessage.set(nonce, salt.length)
    fullMessage.set(box, salt.length + nonce.length)
    const base64FullMessage = encodeBase64(fullMessage)
    return base64FullMessage
  }

  async decrypt (messageWithNonce) {
    const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce)
    const salt = messageWithNonceAsUint8Array.slice(0, SALT_LENGTH)
    const nonce = messageWithNonceAsUint8Array.slice(SALT_LENGTH, SALT_LENGTH + secretbox.nonceLength)
    const message = messageWithNonceAsUint8Array.slice(SALT_LENGTH + secretbox.nonceLength)
    const { key } = await Crypt.deriveKey(this._pass, salt)
    const decrypted = secretbox.open(message, nonce, key)
    if (!decrypted) {
      throw new Error(COULD_NOT_DECRYPT)
    } else {
      return encodeUTF8(decrypted)
    }
  }
}
