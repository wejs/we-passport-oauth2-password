const redisLib = require('redis'),
  crypto = require('crypto'),
  uuid = require('uuid');

let oauthPlugin;

const redis = {
	init(plugin, we, done) {
    oauthPlugin = plugin;
    const cfgs = we.config['oauth2-password-grant'];
    //CREATE REDIS CLIENTS
    plugin.redisClientAccess = redisLib.createClient({
      host: process.env.REDIS_HOST || cfgs.redis.host,
      port: process.env.REDIS_PORT || cfgs.redis.port
    });
    plugin.redisClientAccess.select(6, (err, res)=> {
      if (err) {
        console.error('Error on select redis DB 6', res);
        throw err;
      }
    });

    plugin.redisClientRefresh = redisLib.createClient({
      host: process.env.REDIS_HOST || cfgs.redis.host,
      port: process.env.REDIS_PORT || cfgs.redis.port
    });
    plugin.redisClientRefresh.select(7, (err, res)=> {
      if (err) {
        console.error('Error on select redis DB 7', res);
        throw err;
      }
    });

    done();
	},

  findUserWithToken(access_token, plugin, done) {
    oauthPlugin.redisClientAccess.get(access_token, (err, data)=> {
      if (err) return done(err);

      if (!data) {
        return done(null, false, {
          error_context: 'authentication',
          error: 'invalid_grant'
        });
      }

      let token;

      try {
        token = JSON.parse(data);
      } catch(e) {
        plugin.we.log.error('we-passport-oauth2-password: error on parse redis data:', data);
        done(null, false, {
          error_context: 'authentication',
          error: 'invalid_grant'
        });
        return null;
      }

      plugin.we.db.models.user.findById(token.ownerId)
      .then( (user)=> {
        if (!user) {
          done(null, false, {
            error_context: 'authentication',
            error: 'invalid_grant'
          });
        } else {
          done(null, user);
        }

        return null;
      })
      .catch(done);
    });
  },

  /**
   * Generate token method
   *
   * @param  {Object}   we   we.js app
   * @param  {Object}   user User data
   * @param  {Function} cb   Callback
   * @return {Null}
   */
  generateToken(we, user, cb) {
    const expireDate = we.utils.moment().add(
      we.config.passport.strategies['oauth2-password-grant'].expires_in,
      'seconds'
    ).toISOString();

    const access_token = uuid.v4() + crypto.randomBytes(35).toString('hex');
    const refresh_token = uuid.v4() + crypto.randomBytes(35).toString('hex');
    const data = {
      id: access_token,
      ownerId: user.id,
      access_token: access_token,
      refresh_token: refresh_token,
      token_type: '',
      scopes: [],
      expireDate: expireDate
    };

    const dataString = JSON.stringify(data);

    oauthPlugin.redisClientAccess.set(
      access_token,
      dataString,
      'EX',
      we.config.passport.strategies['oauth2-password-grant'].expires_in
    );

    oauthPlugin.redisClientRefresh.set(
      refresh_token,
      dataString,
      'EX',
      we.config.passport.strategies['oauth2-password-grant'].expires_in
    );

    cb(null, data);
  },

  /**
   * Refresh one token if is valid
   *
   * @param  {Object}   plugin
   * @param  {Object}   refresh_token
   * @param  {Function} cb   Callback
   * @return {Null}
   */
  refreshToken(plugin, refresh_token, done) {
    oauthPlugin.redisClientRefresh.get(refresh_token, (err, data)=> {
      if (err) return done(err);

      if (!data) {
        return done({
          error_context: 'authentication',
          error: 'invalid_grant',
          error_description_code: 'oauth2-password-grant.refresh_token.invalid'
        });
      }

      let token;

      try {
        token = JSON.parse(data);
      } catch(e) {
        plugin.we.log.error('we-passport-oauth2-password: error on parse redis data:', data);
        done(null, false, {
          error_context: 'authentication',
          error: 'invalid_grant'
        });
        return null;
      }

      plugin.we.db.models.user.findById(token.ownerId)
      .then( (owner)=> {
        if (!owner) {
          done(null, false, {
            error_context: 'authentication',
            error: 'invalid_grant'
          });
          return null;
        }

        plugin.storage.generateToken(plugin.we, owner, (err, tokenRecord)=> {
          if (err) return done(err);

          done(null, {
            access_token: tokenRecord.access_token,
            refresh_token: tokenRecord.refresh_token,
            token_type: tokenRecord.token_type,
            scopes: tokenRecord.scopes,
            expires_in: plugin.we.config.passport.strategies['oauth2-password-grant'].expires_in, // ms
            // refresh_token: ''
            user: owner
          });

          // delete old access and refresh tokens:
          oauthPlugin.redisClientRefresh.del(refresh_token);
          oauthPlugin.redisClientAccess.del(token.access_token);

          return null;
        });

        return null;
      })
      .catch(done);

    });
  }
};

module.exports = redis;