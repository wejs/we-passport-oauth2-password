# We.js Passport oauth2 password grant strategy plugin

This plugin adds suport for local authentication with password grant type in we.js projects.

The client credentials grant type provides an application a way to access its own service account. Examples of when this might be useful include if an application wants to update its registered description or redirect URI, or access other data stored in its service account via the API.

Compatible with: https://ember-simple-auth.com client

## Installation

```sh
we i we-passport-oauth2-password
```

## Urls:

### Authenticate
#### POST /auth/grant-password/authenticate

Body params:
- username
- password

Response example:

```js
{
  token_type: 'passportGrantToken',
  access_token: 'tokenString',
  expires_in: 12313, // milisecconds of token life
  // refresh_token: '', // TODO!
  user: req.user // user object
}
```

## Configuration

```
// ...
    'oauth2-password-grant': {
      storage: 'sequelize', // sequelize || redis
      redis: {
        host: null,
        port: null,
        password: null
        // see https://github.com/NodeRedis/node_redis#rediscreateclient for all options
      }
    },

    passport: {
      strategies: {
        // session
        'oauth2-password-grant': {
          expires_in: 1800, // secconds
        }
      }
    }
// ...
```

## ROADMAP

- Add revoke token url
- Add delete  invalid tokens every time

## Links

- We.js site: http://wejs.org
- Resource Owner Password Credentials Grant SPEC: https://tools.ietf.org/html/rfc6749#section-4.3

## Copyright and license

Copyright Alberto Souza <contato@albertosouza.net> and contributors , under [the MIT license](https://github.com/wejs/we-core/blob/master/LICENSE.md).