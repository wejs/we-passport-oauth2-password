/**
 * Plugin.js file, set configs, routes, hooks and events here
 *
 * see http://wejs.org/docs/we/plugin
 */

module.exports = function loadPlugin(projectPath, Plugin) {
  var plugin = new Plugin(__dirname);

  // passport.use(new PasswordGrantStrategy(plugin.we.config.appKeys.oauth2GrandPassword,
  // function(accessToken, refreshToken, profile, done) {
  //   done(null, profile);
  // });

  // set plugin configs
  plugin.setConfigs({
    passport: {
      strategies: {
        // session

        // passwordGrant: {
        //   Strategy: PasswordGrantStrategy,
        //   tokenURL: plugin.we.config.hostname + '/auth/grant-password/authenticate',
        //   clientID: 'EXAMPLE_CLIENT_ID',
        //   findUser: function findUser(accessToken, refreshToken, profile, done) {

        //     console.log('on find ...');

        //   }
        // }
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

    // for dev env ...
    if (we.env == 'test') {
      // Some secure method
      we.express.get('/auth/grant-password/protected', function (req, res) {
        if (req.isAuthenticated()) {
          res.send({ authenticated: true });
        } else {
          res.send({ authenticated: false });
        }
      });
    }
  });

  return plugin;
};