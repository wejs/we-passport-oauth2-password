module.exports = {
  authenticate: function authenticate(req, res) {
    if (!req.body.email && req.body.username)
      req.body.email = req.body.username;

    req.we.passport.authenticate('local')(req, res, function (err, user, info) {

      if (err) return res.serverError(err);
      // TODO add message here ...
      if (!user) return res.badRequest(info);

      var expireDate = req.we.utils.moment().add(
        req.we.config.passport.strategies['oauth2-password-grant'].expires_in,
        'miliseconds'
      ).format();

      req.we.db.models.passportGrantToken.create({
        ownerId: req.user.id,
        expireDate: expireDate
      }, {
        raw: true
      })
      .then( function(tokenRecord) {

        res.status(200).send({
          token_type: 'passportGrantToken',
          access_token: tokenRecord.token,
          expires_in: req.we.config.passport.strategies['oauth2-password-grant'].expires_in, // ms
          // refresh_token: ''
          user: req.user
        });

        return null;
      })
      .catch(res.queryError);
    });
  }
}