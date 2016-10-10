var assert = require('assert');
var request = require('supertest');
var helpers = require('we-test-tools').helpers;
var stubs = require('we-test-tools').stubs;
var http;
var we;
var agent;

describe('passport-oauth2-password-grant', function() {
  var salvedUser, salvedUserPassword;

  before(function (done) {
    http = helpers.getHttp();
    agent = request.agent(http);

    we = helpers.getWe();

    var userStub = stubs.userStub();
    helpers.createUser(userStub, function(err, user) {
      if (err) throw err;

      salvedUser = user;
      salvedUserPassword = userStub.password;

      done(err);
    })
  });

  describe('API', function () {
    it ('Should load passport oauth 2 grant type middleware');
    it ('Should authenticate one user', function(done) {
      var ar = request.agent(http);
      ar.post('/auth/grant-password/authenticate')
      .set('Accept', 'application/json')
      .send({
        grant_type: 'password',
        email: salvedUser.email,
        password: salvedUserPassword
      })
      .expect(200)
      .end(function (err, res) {
        if (err) {
          console.log('<res.text>', res.text);
          throw err;
        }

        assert(res.body.access_token);
        assert(res.body.user);
        assert.equal(res.body.user.id, salvedUser.id);

        done();
      });
    });
    it ('Should request an protected page', function(done) {
      var ar = request.agent(http);
      ar.post('/auth/grant-password/authenticate')
      .set('Accept', 'application/json')
      .send({
        grant_type: 'password',
        email: salvedUser.email,
        password: salvedUserPassword
      })
      .expect(200)
      .end(function (err, res) {
        if (err) {
          console.log('<res.text>', res.text);
          throw err;
        }

        assert(res.body.access_token);
        assert(res.body.user);
        assert.equal(res.body.user.id, salvedUser.id);

        ar.get('/auth/grant-password/protected')
        .set('Accept', 'application/json')
        .set('Authorization', 'Basic ' + res.body.access_token)
        .expect(200)
        .end(function(err, res) {
          if (err) {
            console.log('<res.text>', res.text);
            throw err;
          }

          assert.equal(res.body.authenticated, true, 'Need be authenticated');
          assert.equal(res.body.user.id, salvedUser.id);

          done();
        });
      });
    });
    it ('Should invalidate the token');

    describe('Errors', function() {
      /*
         invalid_request
               The request is missing a required parameter, includes an
               unsupported parameter value (other than grant type),
               repeats a parameter, includes multiple credentials,
               utilizes more than one mechanism for authenticating the
               client, or is otherwise malformed.
      */
      it ('Should return { error: invalid_request } with invalid parameters');

      /*
         invalid_client
               Client authentication failed (e.g., unknown client, no
               client authentication included, or unsupported
               authentication method).  The authorization server MAY
               return an HTTP 401 (Unauthorized) status code to indicate
               which HTTP authentication schemes are supported.  If the
               client attempted to authenticate via the "Authorization"
               request header field, the authorization server MUST
               respond with an HTTP 401 (Unauthorized) status code and
               include the "WWW-Authenticate" response header field
               matching the authentication scheme used by the client.
       */
      it ('Should return { error: invalid_client } with code 401 for client authentication failure');

      /*
         invalid_grant
               The provided authorization grant (e.g., authorization
               code, resource owner credentials) or refresh token is
               invalid, expired, revoked, does not match the redirection
               URI used in the authorization request, or was issued to
               another client.
       */
      it ('Should return { error: invalid_grant } with code 401 for client authentication failure', function(done) {
        var ar = request.agent(http);

        var invalidToken = 'aninvalidtoken';

        ar.get('/auth/grant-password/protected')
        .set('Accept', 'application/json')
        .set('Authorization', 'Basic ' + invalidToken)
        .expect(401)
        .end(function(err, res) {
          if (err) {
            console.log('<res.text>', res.text);
            throw err;
          }

          assert(res.body.error, 'should include error code in body');
          assert.equal(res.body.error, 'invalid_grant', 'error should be invalid_grant');

          done();
        });
      });

      /*
      invalid_scope
               The requested scope is invalid, unknown, malformed, or
               exceeds the scope granted by the resource owner.
       */
      it ('Should return { error: invalid_scope } if The requested scope is invalid, unknown, '+
        'malformed, or exceeds the scope granted by the resource owner.');

      /*
         unsupported_grant_type
               The authorization grant type is not supported by the
               authorization server.
      */

      it ('Should return { error: unsupported_grant_type } if grant type is not set', function(done) {

        var ar = request.agent(http);
        ar.post('/auth/grant-password/authenticate')
        .set('Accept', 'application/json')
        .send({
          email: salvedUser.email,
          password: salvedUserPassword
        })
        .expect(400)
        .end(function (err, res) {
          if (err) {
            console.log('<res.text>', res.text);
            throw err;
          }

          assert(res.body.error, 'should include error code in body');
          assert.equal(res.body.error, 'unsupported_grant_type', 'error should be unsupported_grant_type');
          assert.equal(res.body.error_description_code, 'oauth2-password-grant.grant_type.invalid.or.not.set');

          done();
        });
      });

      it ('Should return { error: unsupported_grant_type } if grant type is invalid', function(done) {

        var ar = request.agent(http);
        ar.post('/auth/grant-password/authenticate')
        .set('Accept', 'application/json')
        .send({
          grand_type: 'authentication',
          email: salvedUser.email,
          password: salvedUserPassword
        })
        .expect(400)
        .end(function (err, res) {
          if (err) {
            console.log('<res.text>', res.text);
            throw err;
          }

          assert(res.body.error, 'should include error code in body');
          assert.equal(res.body.error, 'unsupported_grant_type', 'error should be unsupported_grant_type');
          assert.equal(res.body.error_description_code, 'oauth2-password-grant.grant_type.invalid.or.not.set');

          done();
        });
      });

    });
  });
});