var assert = require('assert');
var request = require('supertest');
var helpers = require('we-test-tools').helpers;
var stubs = require('we-test-tools').stubs;
var http;
var we;
var agent;

describe('passport-oauth2-password-grant', function() {
  var salvedUser, salvedUserPassword, authenticatedRequest;

  before(function (done) {
    http = helpers.getHttp();
    agent = request.agent(http);

    we = helpers.getWe();

    var userStub = stubs.userStub();
    helpers.createUser(userStub, function(err, user) {
      if (err) throw err;

      salvedUser = user;
      salvedUserPassword = userStub.password;

      // login user and save the browser
      // authenticatedRequest = request.agent(http);
      // authenticatedRequest.post('/login')
      // .set('Accept', 'application/json')
      // .send({
      //   email: salvedUser.email,
      //   password: salvedUserPassword
      // })
      // .expect(200)
      // .set('Accept', 'application/json')
      // .end(function (err) {
        done(err);
      //});
    })
  });

  describe('API', function () {
    it ('Should load passport oauth 2 grant type middleware');
    it ('Should authenticate one user', function(done) {
      var ar = request.agent(http);
      ar.post('/auth/grant-password/authenticate')
      .set('Accept', 'application/json')
      .send({
        email: salvedUser.email,
        password: salvedUserPassword
      })
      // .expect(200)
      .end(function (err, res) {
        console.log('<f>', err, res.text);
        done(err);
      });
    });
    it ('Should request an protected page');
    it ('Should invalidate the token');
  });
});