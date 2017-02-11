function generateToken(we, user, cb) {
  const expireDate = we.utils.moment().add(
    we.config.passport.strategies['oauth2-password-grant'].expires_in,
    'seconds'
  ).toISOString();

  we.db.models.passportGrantToken
  .create({
    ownerId: user.id,
    expireDate: expireDate
  }, {
    raw: true
  })
  .then( (tokenRecord)=> {
    cb(null, tokenRecord);
    return null;
  })
  .catch(cb);

  return null;
}

module.exports = generateToken;