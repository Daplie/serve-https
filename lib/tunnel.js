'use strict';

module.exports.create = function (opts/*, servers*/) {
  // servers = { plainserver, server }
  var tunnel = require('daplie-tunnel');
  var stunnel = require('stunnel');


  return tunnel.token({
    refreshToken: opts.refreshToken
  , email: opts.email
  , domains: [ opts.servername ]
  }).then(function (result) {
    // { jwt, tunnelUrl }
    stunnel.connect({
      token: result.jwt
    , stunneld: result.tunnelUrl
    , locals: [
        { protocol: 'https'
        , hostname: opts.servername
        , port: opts.port
        }
      , { protocol: 'http'
        , hostname: opts.servername
        , port: opts.insecurePort || opts.port
        }
      ]
    });
  });
};
