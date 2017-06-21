/**
 * We.js Passport oauth2 password grant strategy
 *
 * see http://wejs.org/docs/we/plugin
 */

const Strategy = require('./lib/Strategy'),
  path = require('path');

module.exports = function loadPlugin(projectPath, Plugin) {
  const plugin = new Plugin(__dirname);

  plugin.fastLoader = function fastLoader(we, done) {
    const cfgs = we.config['oauth2-password-grant'];

    plugin.storage = require( path.join(__dirname, 'lib/storage', cfgs.storage) );

    if (!plugin.storage) {
      return done(`we-passport-oauth2-strategy:Invalid storage ${cfgs.storage}`);
    }
    // controllers:
    we.controllers.passwordOauth2GrantStrategy = new we.class.Controller({
      /**
       * Passport oauth 2 authentication action
       *
       * @apiName passwordOauth2GrantStrategy.authenticate
       * @apiGroup passwordOauth2GrantStrategy
       *
       * @module Controller
       *
       * @param {Object} `req` Express.js request
       * @param {Object} `res` Express.js response
       * @param  {Function} next Express.js next middleware callback
       */
      authenticate(req, res, next) {
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
        .authenticate('local', (err, user, info)=> {
          if (err) return res.serverError(err);
          if (!req.user && user) req.user = user;
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

          plugin.storage.generateToken(req.we, req.user, (err, tokenRecord)=> {
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

      /**
       * Passport oauth 2 refresh token action
       *
       * @apiName passwordOauth2GrantStrategy.refreshToken
       * @apiGroup passwordOauth2GrantStrategy
       *
       * @module Controller
       *
       * @param {Object} `req` Express.js request
       * @param {Object} `res` Express.js response
       * @param  {Function} next Express.js next middleware callback
       */
      refreshToken(req, res) {
        plugin.storage.refreshToken(
          plugin,
          req.body.refresh_token,
          function(err, data) {
            if (err) {

              if (err.error_description_code == 'oauth2-password-grant.refresh_token.invalid') {
                // invalid or not found refresh token
                return res.status(401).send(err);
              }

              return res.queryError(err);
            }
            // success
            res.status(200).send(data);
          }
        );
      },

      /**
       * Protected route only for tests
       */
      protectedRoute(req, res) {
        if (req.isAuthenticated()) {
          res.send({ authenticated: true, user: req.user });
        } else {
          res.send({ authenticated: false });
        }
      }
    });

    plugin.storage.init(plugin, we, done);
  };

  // set plugin configs
  plugin.setConfigs({
    'oauth2-password-grant': {
      storage: 'sequelize', // sequelize || redis
      redis: {
        host: null,
        port: null
      }
    },

    passport: {
      strategies: {
        // session
        'oauth2-password-grant': {
          expires_in: 1800, // secconds
          Strategy: Strategy,
          findUser(access_token, done) {
            return plugin.storage.findUserWithToken(access_token, plugin, done);
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