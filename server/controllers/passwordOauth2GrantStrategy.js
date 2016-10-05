module.exports = {
  authenticate: function authenticate(req, res, next) {
    var username = req.body.email,
        password = req.body.password;

    req.we.passport.authenticate('local', {
      username: username,
      password: password,
      session: false
    })(req, res, function(err) {
      if (err) return res.serverError(err);

      console.log('<>', req.user);
      console.log('<session>', req.session);

      req.we.db.models.passwordGrantToken.create({
        ownerId: req.user.id
      })
      .then( function(tokenRecord) {

        res.status(200).send(req.user);

        return null;
      })
      .catch(res.queryError);
    });
  }
}