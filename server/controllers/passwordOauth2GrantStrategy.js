var generateToken = require('../../lib/generateToken');

module.exports = {
  authenticate: function authenticate(req, res, next) {
    if (!req.body.email && req.body.username)
      req.body.email = req.body.username;

    if (req.body.grant_type == 'refresh_token') {
      return req.we.controllers.passwordOauth2GrantStrategy.refreshToken(req, res, next);
    } else if (
      !req.body.grant_type ||
      (req.body.grant_type != 'password')
    ) {
      return res.status(400).send({
        error_context: 'authentication',
        error: 'unsupported_grant_type',
        error_description_code: 'oauth2-password-grant.grant_type.invalid.or.not.set'
      });
    }

    req.we.passport
    .authenticate('local', function (err, user, info) {
      if (err) return res.serverError(err);
      // TODO add message here ...
      if (!req.user && info) {
        if (info.message) {
          res.addMessage('error', {
            // i18n string
            text: info.message,
            // vars avaible in i18n string
            vars: info
          });
          return res.badRequest(info);
        } else {
          return res.status(401).send(info);
        }
      }

      generateToken(req.we, req.user, function(err, tokenRecord) {
        if (err) return res.queryError(err);

        res.status(200).send({
          access_token: tokenRecord.access_token,
          refresh_token: tokenRecord.refresh_token,
          token_type: tokenRecord.token_type,
          scopes: tokenRecord.scopes,
          expires_in: req.we.config.passport.strategies['oauth2-password-grant'].expires_in, // ms
          // refresh_token: ''
          user: req.user
        });

        return null;
      });
    })(req, res, next);
  },

  refreshToken: function refreshToken(req, res) {
    var models = req.we.db.models;

    models.passportGrantToken.findOne({
      where: {
        refresh_token: req.body.refresh_token,
        isValid: true
      },
      include: [{
        model: models.user,
        as: 'owner'
      }]
    })
    .then(function(token) {

      if (!token) {
        return res.status(401).send({
          error_context: 'authentication',
          error: 'invalid_grant',
          error_description_code: 'oauth2-password-grant.refresh_token.invalid'
        });
      } else {
        generateToken(req.we, token.owner, function(err, tokenRecord) {
          if (err) return res.queryError(err);

          res.status(200).send({
            access_token: tokenRecord.access_token,
            refresh_token: tokenRecord.refresh_token,
            token_type: tokenRecord.token_type,
            scopes: tokenRecord.scopes,
            expires_in: req.we.config.passport.strategies['oauth2-password-grant'].expires_in, // ms
            // refresh_token: ''
            user: token.owner
          });

          // invalidate the token after generate the new token
          token.isValid = false;
          token.save();

          return null;
        });
      }

      return null;
    })
    .catch(res.queryError);
  },

  /**
   * Protected route only for tests
   */
  protectedRoute: function protectedRoute(req, res) {
    if (req.isAuthenticated()) {
      res.send({ authenticated: true, user: req.user });
    } else {
      res.send({ authenticated: false });
    }
  }
}