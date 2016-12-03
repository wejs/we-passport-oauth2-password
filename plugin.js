/**
 * We.js Passport oauth2 password grant strategy
 *
 * see http://wejs.org/docs/we/plugin
 */

var Strategy = require('./lib/Strategy');

module.exports = function loadPlugin(projectPath, Plugin) {
  var plugin = new Plugin(__dirname);

  // set plugin configs
  plugin.setConfigs({
    passport: {
      strategies: {
        // session
        'oauth2-password-grant': {
          expires_in: 1800, // secconds
          Strategy: Strategy,
          findUser: function findUser(access_token, done) {

            this.we.db.models.passportGrantToken.findOne({
              where: {
                access_token: access_token,
                expireDate: {
                  $gte: this.we.db.defaultConnection.fn('NOW')
                },
                isValid: true
              },
              include: [{ model: this.we.db.models.user, as: 'owner' }]
            })
            .then(function(token) {
              if (!token) {
                done(null, false, {
                  error_context: 'authentication',
                  error: 'invalid_grant'
                });
              } else {
                done(null, token.owner);
              }

              return null;
            })
            .catch(done);

            return null;
          }
        }
      }
    }
  });

  // plugin routes
  plugin.setRoutes({
    'post /auth/grant-password/authenticate': {
      controller: 'passwordOauth2GrantStrategy',
      action: 'authenticate'
    }
  });

  plugin.oauth2PassportGrantMD = function (req, res, next) {
    req.we.passport.authenticate('oauth2-password-grant', function afterCheckToken (err, user, info) {
      if (err) return res.serverError(err);

      if (info) {
        req.we.log.verbose('OAuth2password:afterCheckToken:', info);

        res.status(401).send(info);

      } else {
        // set is is authenticated
        if (user) req.user = user;
        next();
      }

      return null;
    })(req, res, next);
  }

  plugin.events.on('router:route:after:cors:middleware', function onSetACLMiddlewareExpress(ctx) {
    ctx.middlewares.push(plugin.oauth2PassportGrantMD);
  });

  plugin.events.on('we:after:load:passport', function afterLoadExpress(we) {
    // for dev env ...
    if (we.env == 'test') {
      // Some secure method
      we.express.get('/auth/grant-password/protected', function (req, res) {
        if (req.isAuthenticated()) {
          res.send({ authenticated: true, user: req.user });
        } else {
          res.send({ authenticated: false });
        }
      });
    }
  });

  return plugin;
};