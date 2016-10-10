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
          expires_in: 1800, // ms
          Strategy: Strategy,
          findUser: function findUser(access_token, done) {

            this.we.db.models.passportGrantToken.findOne({
              where: {
                access_token: access_token,
                expireDate: { $gte: new Date() }
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

  plugin.events.on('we:after:load:passport', function afterLoadExpress(we) {

    we.express.use(function (req, res, next) {
      we.passport.authenticate('oauth2-password-grant', function afterCheckToken (err, user, info) {
        if (err) return res.serverError(err);

        if (info) {
          req.we.log.verbose('OAuth2password:afterCheckToken:', err, info);
          return res.status(401).send(info);
        }

        // set is is authenticated
        if (user) req.user = user;

        next();
      })(req, res, next);
    });

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