const crypto = require('crypto'),
  uuid = require('uuid');

const sequelize = {
  init(plugin, we, done) {
    // model hooks
    we.db.modelHooks.createPassportGrantToken = function createPassportGrantToken (record) {
      // unique random strings for tokens
      if (!record.isNewRecord || record.access_token)  return record;
      record.access_token = uuid.v4() + crypto.randomBytes(35).toString('hex');
      record.refresh_token = uuid.v4() + crypto.randomBytes(35).toString('hex');
    };

    // JSON model
    we.db.modelsConfigs.passportGrantToken = we.db.defineModelFromJson( {
      'attributes': {
        'access_token': {
          'type': 'STRING',
          'unique': true,
          'allowNull': false
        },
        'refresh_token': {
          'type': 'STRING',
          'unique': true,
          'allowNull': false
        },
        'token_type': {
          'type': 'STRING'
        },
        'scopes': {
          'type': 'TEXT'
        },
        'expireDate': {
          'type': 'DATE',
          'allowNull': false
        },
        'isValid': {
          'type': 'BOOLEAN',
          'defaultValue': true
        }
      },
      'associations': {
        'owner': {
          'type': 'belongsTo',
          'model': 'user',
          'allowNull': false
        }
      },
      'hooks': {
        'beforeValidate': ['createPassportGrantToken']
      }
    }, we);

    done();
  },

  findUserWithToken(access_token, plugin, done) {
    const we = plugin.we;

    let gte = we.db.defaultConnection.fn('NOW');

    if (we.db.activeConnectionConfig.dialect == 'sqlite') {
      gte = new Date();
    }

    we.db.models.passportGrantToken
    .findOne({
      where: {
        access_token: access_token,
        expireDate: {
          [we.Op.gte]: gte
        },
        isValid: true
      },
      include: [{ model: we.db.models.user, as: 'owner' }]
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
  },
  /**
   * Refresh one token if is valid
   *
   * @param  {Object}   plugin
   * @param  {Object}   refresh_token
   * @param  {Function} cb   Callback
   * @return {Null}
   */
  refreshToken(plugin, refresh_token, cb) {
    const models = plugin.we.db.models;

    models.passportGrantToken.findOne({
      where: {
        refresh_token: refresh_token,
        isValid: true
      },
      include: [{
        model: models.user,
        as: 'owner'
      }]
    })
    .then( (token)=> {

      if (!token) {
        cb({
          error_context: 'authentication',
          error: 'invalid_grant',
          error_description_code: 'oauth2-password-grant.refresh_token.invalid'
        });
      } else {
        plugin.storage.generateToken(plugin.we, token.owner, (err, tokenRecord)=> {
          if (err) return cb(err);

          cb(null, {
            access_token: tokenRecord.access_token,
            refresh_token: tokenRecord.refresh_token,
            token_type: tokenRecord.token_type,
            scopes: tokenRecord.scopes,
            expires_in: plugin.we.config.passport.strategies['oauth2-password-grant'].expires_in, // ms
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
    .catch(cb);

    return null;
  }
};

module.exports = sequelize;