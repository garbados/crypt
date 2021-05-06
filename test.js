/* global describe, it */
const assert = require('assert').strict
const Crypt = require('.')

const PLAINTEXT = 'hello world'
const PASSWORD = 'password'
const BENCHMARK = 1e2 // note: 1eN = 1 and N zeroes (ex: 1e2 = 100)

describe('crypt', function () {
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
    this.timeout(0)
    const crypt = new Crypt(PASSWORD)
    for (let i = 0; i < BENCHMARK; i++) {
      const ciphertext = await crypt.encrypt(PLAINTEXT)
      const decryptext = await crypt.decrypt(ciphertext)
      assert.strictEqual(decryptext, PLAINTEXT)
    }
  })
})
