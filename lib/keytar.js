var keytar = require('../build/Release/keytar.node')

function checkRequired(val, name) {
  if (!val || val.length <= 0) {
    throw new Error(name + ' is required.');
  }
}

module.exports = {
  getPassword: function (service, account, legacy) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')
    checkRequired(legacy,  'Legacy')

    return keytar.getPassword(service, account, legacy)
  },

  setPassword: function (service, account, password, legacy) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')
    checkRequired(password, 'Password')
    checkRequired(legacy,   'Legacy')

    return keytar.setPassword(service, account, password, legacy)
  },

  deletePassword: function (service, account, legacy) {
    checkRequired(service, 'Service')
    checkRequired(account, 'Account')
    checkRequired(legacy,  'Legacy')

    return keytar.deletePassword(service, account, legacy)
  },

  findPassword: function (service) {
    checkRequired(service, 'Service')

    return keytar.findPassword(service)
  },

  findCredentials: function (service) {
    checkRequired(service, 'Service')

    return keytar.findCredentials(service)
  }
}
