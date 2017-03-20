/**
 * We.js Passport oauth2 password grant strategy
 *
 * see http://wejs.org/docs/we/plugin
 */

const Strategy = require('./lib/Strategy');

module.exports = function loadPlugin(projectPath, Plugin) {
  const plugin = new Plugin(__dirname);
  // Set the generate token method for reuse in others plugins:
  plugin.generateToken = require('./lib/generateToken');

  // set plugin configs
  plugin.setConfigs({
    passport: {
      strategies: {
        // session
        'oauth2-password-grant': {
          expires_in: 1800, // secconds
          Strategy: Strategy,
          findUser(access_token, done) {

            this.we.db.models.passportGrantToken
            .findOne({
              where: {
                access_token: access_token,
                expireDate: {
                  $gte: this.we.db.defaultConnection.fn('NOW')
                },
                isValid: true
              },
              include: [{ model: this.we.db.models.user, as: 'owner' }]
            })
            .then( (token)=> {
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

  const routes = {
    'post /auth/grant-password/authenticate': {
      controller: 'passwordOauth2GrantStrategy',
      action: 'authenticate',
      responseType: 'json'
    }
  };

  // for dev env ...
  if (plugin.we.env == 'test') {
    routes['get /auth/grant-password/protected'] = {
      controller: 'passwordOauth2GrantStrategy',
      action: 'protectedRoute',
      responseType: 'json'
    };
  }

  // plugin routes
  plugin.setRoutes(routes);

  plugin.oauth2PassportGrantMD = function oauth2PassportGrantMD(req, res, next) {
    req.we.passport
    .authenticate('oauth2-password-grant', function afterCheckToken (err, user, info) {
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
  };

  // add the middleware in every route after CORST
  plugin.events.on('router:route:after:cors:middleware', function onSetACLMiddlewareExpress(ctx) {
    ctx.middlewares.push(plugin.oauth2PassportGrantMD);
  });

  return plugin;
};