const assert = require('assert').strict
const Crypt = require('.')

 // constants; see test.js
const PLAINTEXT = 'hello world'
const PASSWORD = 'password'
const BENCHMARK = 1e4

Promise.resolve().then(async () => {
  const start = Date.now()
  const crypt = new Crypt(PASSWORD)
  for (let i = 0; i < BENCHMARK; i++) {
    const ciphertext = await crypt.encrypt(PLAINTEXT)
    const decryptext = await crypt.decrypt(ciphertext)
    assert.strictEqual(decryptext, PLAINTEXT)
  }
  console.log(`${BENCHMARK} round-trip operations took ${Date.now() - start}ms`)
})
