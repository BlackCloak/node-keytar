var assert = require('chai').assert
var keytar = require('../')

describe("keytar", function() {
  var service = 'keytar tests'
  var service2 = 'other tests'
  var account = 'buster'
  var password = 'secret'
  var account2 = 'buster2'
  var password2 = 'secret2'
  var mode = 'non-legacy'

  var object = {}
  object.toString = function () {
    throw new Error("Whoops! Time to seg fault")
  }

  beforeEach(async function() {
    await keytar.deletePassword(service, account, mode),
    await keytar.deletePassword(service, account2, mode)
    await keytar.deletePassword(service2, account, mode)

  })

  afterEach(async function() {
    await keytar.deletePassword(service, account, mode),
    await keytar.deletePassword(service, account2, mode)
    await keytar.deletePassword(service2, account, mode)
  })

  describe("setPassword/getPassword(service, account)", function() {
    it("sets and yields the password for the service and account", async function() {
      await keytar.setPassword(service, account, password, mode)
      assert.equal(await keytar.getPassword(service, account, mode), password)
      await keytar.setPassword(service, account, password2, mode)
      assert.equal(await keytar.getPassword(service, account, mode), password2)
    })

    it("yields null when the password was not found", async function() {
      assert.equal(await keytar.getPassword(service, account, mode), null)
    })

    describe("error handling", function () {
      describe('setPassword', () => {
        it("handles when an object is provided for service", async function () {
          try {
            await keytar.setPassword(object, account, password, mode)
          } catch (err) {
            assert.equal(err.message, "Parameter 'service' must be a string")
          }
        })

        it("handles when an object is provided for username", async function () {
          try {
            await keytar.setPassword(service, object, password, mode)
          } catch (err) {
            assert.equal(err.message, "Parameter 'username' must be a string")
          }
        })

        it("handles when an object is provided for password", async function () {
          try {
            await keytar.setPassword(service, account, object, mode)
          } catch (err) {
            assert.equal(err.message, "Parameter 'password' must be a string")
          }
        })
      })

      describe('getPassword', () => {
        it("handles when an object is provided for service", async function () {
          try {
            await keytar.getPassword(object, account, mode)
          } catch (err) {
            assert.equal(err.message, "Parameter 'service' must be a string")
          }
        })

        it("handles when an object is provided for username", async function () {
          try {
            await keytar.getPassword(service, object, mode)
          } catch (err) {
            assert.equal(err.message, "Parameter 'username' must be a string")
          }
        })
      })
    })

    describe("Unicode support", function() {
      const service = "se®vi\u00C7e"
      const account = "shi\u0191\u2020ke\u00A5"
      const password = "p\u00E5ssw\u00D8®\u2202"

      it("handles unicode strings everywhere", async function() {
        await keytar.setPassword(service, account, password, mode)
        assert.equal(await keytar.getPassword(service, account, mode), password)
      })

      afterEach(async function() {
        await keytar.deletePassword(service, account, mode)
      })
    })
  })

  describe("deletePassword(service, account)", function() {
    it("yields true when the password was deleted", async function() {
      await keytar.setPassword(service, account, password, mode)
      assert.equal(await keytar.deletePassword(service, account, mode), true)
    })

    it("yields false when the password didn't exist", async function() {
      assert.equal(await keytar.deletePassword(service, account, mode), false)
    })

    describe("error handling", function () {
      it("handles when an object is provided for service", async function () {
        try {
          await keytar.deletePassword(object, account, mode)
        } catch (err) {
          assert.equal(err.message, "Parameter 'service' must be a string")
        }
      })

      it("handles when an object is provided for username", async function () {
        try {
          await keytar.deletePassword(service, object, mode)
        } catch (err) {
          assert.equal(err.message, "Parameter 'username' must be a string")
        }
      })
    })
  })

  describe("findPassword(service)", function() {
    this.timeout(5000);

    it("yields a password for the service", async function() {
      await keytar.setPassword(service, account, password, mode),
      await keytar.setPassword(service, account2, password2, mode)
      assert.include([password, password2], await keytar.findPassword(service))
    })

    it("yields null when no password can be found", async function() {
      assert.equal(await keytar.findPassword(service), null)
    })

    it("handles when an object is provided for service", async function () {
      try {
        await keytar.findPassword(object)
      } catch (err) {
        assert.equal(err.message, "Parameter 'service' must be a string")
      }
    })
  })

  describe('findCredentials(service)', function() {
    it('yields an array of the credentials', async function() {
      await keytar.setPassword(service, account, password, mode)
      await keytar.setPassword(service, account2, password2, mode)
      await keytar.setPassword(service2, account, password, mode)

      const found = await keytar.findCredentials(service)
      const sorted = found.sort(function(a, b) {
        return a.account.localeCompare(b.account)
      })

      assert.deepEqual([{account: account, password: password}, {account: account2, password: password2}], sorted)
    });

    it('returns an empty array when no credentials are found', async function() {
      const accounts = await keytar.findCredentials(service)
      assert.deepEqual([], accounts)
    })

    it("handles when an object is provided for service", async function () {
      try {
        await keytar.findCredentials(object)
      } catch (err) {
        assert.equal(err.message, "Parameter 'service' must be a string")
      }
    })

    describe("Unicode support", function() {
      const service = "se®vi\u00C7e"
      const account = "shi\u0191\u2020ke\u00A5"
      const password = "p\u00E5ssw\u00D8®\u2202"

      it("handles unicode strings everywhere", async function() {
        await keytar.setPassword(service, account, password)
        await keytar.setPassword(service, account2, password2)

        const found = await keytar.findCredentials(service)
        const sorted = found.sort(function(a, b) {
          return a.account.localeCompare(b.account)
        })

        assert.deepEqual([{account: account2, password: password2}, {account: account, password: password}], sorted)
      })

      afterEach(async function() {
        await keytar.deletePassword(service, account)
      })
    })
  });
})
