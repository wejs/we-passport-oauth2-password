var crypto = require('crypto');
var uuid = require('uuid');

module.exports = function createPassportGrantToken (record, options, done) {
  // random string
  record.token = uuid.v4() + crypto.randomBytes(35).toString('hex');

  return done();
}
