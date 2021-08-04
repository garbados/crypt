/* global describe, it */
const assert = require('assert').strict
const { encodeBase64 } = require('tweetnacl-util')
const Crypt = require('.')

const PLAINTEXT = 'hello world'
const PASSWORD = 'password'
const BENCHMARK = 1e4 // note: 1e4 = 1 and 4 zeroes (10,000)

describe('crypt', function () {
  this.timeout(1000 * 10) // 10 seconds
  
  it('should derive a key from a password', async function () {
    let { key, salt } = await Crypt.deriveKey(PASSWORD)
    key = encodeBase64(key)
    assert.equal(typeof key, 'string')
    let { key: key2 } = await Crypt.deriveKey(PASSWORD, salt)
    key2 = encodeBase64(key2)
    assert.equal(key, key2)
  })

  it('should require a password', function () {
    let ok = false
    try {
      const crypt = new Crypt()
      throw new Error(`crypt created: ${!!crypt}`)
    } catch (error) {
      if (error.message === 'A password is required for encryption or decryption.') {
        ok = true
      }
    }
    assert(ok)
  })

  it('should do the crypto dance', async function () {
    const crypt = new Crypt(PASSWORD)
    const ciphertext = await crypt.encrypt(PLAINTEXT)
    const decryptext = await crypt.decrypt(ciphertext)
    assert.strictEqual(decryptext, PLAINTEXT)
  })

  it('should fail to decrypt ok', async function () {
    const crypt = new Crypt(PASSWORD)
    const crypt2 = new Crypt(PASSWORD + 'a')
    const ciphertext = await crypt.encrypt(PLAINTEXT)
    let failed = false
    try {
      await crypt2.decrypt(ciphertext)
    } catch (e) {
      assert.equal(e.message, 'Could not decrypt!')
      failed = true
    }
    assert(failed)
  })

  it(`should do the crypto dance ${BENCHMARK} times`, async function () {
    this.timeout(BENCHMARK * 10) // assume each op will take no more than 10ms
    const crypt = new Crypt(PASSWORD)
    for (let i = 0; i < BENCHMARK; i++) {
      const ciphertext = await crypt.encrypt(PLAINTEXT)
      const decryptext = await crypt.decrypt(ciphertext)
      assert.strictEqual(decryptext, PLAINTEXT)
    }
  })

  it('should export to a string', async function () {
    const crypt = new Crypt(PASSWORD)
    const exportString = await crypt.export()
    assert.equal(typeof exportString, 'string')
  })

  it('should import from an export payload', async function () {
    const crypt1 = new Crypt(PASSWORD)
    const exportString = await crypt1.export()
    const crypt2 = await Crypt.import(PASSWORD, exportString)
    const encrypted = await crypt1.encrypt(PLAINTEXT)
    const decrypted = await crypt2.decrypt(encrypted)
    assert.equal(decrypted, PLAINTEXT)
  })
})
