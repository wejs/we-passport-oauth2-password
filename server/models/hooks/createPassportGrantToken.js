const crypto = require('crypto'),
  uuid = require('uuid');

module.exports = function createPassportGrantToken (record, options, done) {
  // unique random strings for tokens
  if (!record.isNewRecord || record.access_token)  return done();

  record.access_token = uuid.v4() + crypto.randomBytes(35).toString('hex');

  record.refresh_token = uuid.v4() + crypto.randomBytes(35).toString('hex');

  return done();
};