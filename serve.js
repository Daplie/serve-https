#!/usr/bin/env node
'use strict';

//var PromiseA = global.Promise;
var PromiseA = require('bluebird');
var https = require('httpolyglot');
var http = require('http');
var fs = require('fs');
var path = require('path');
var httpPort = 80;
var httpsPort = 443;
var lrPort = 35729;
var portFallback = 8443;
var insecurePortFallback = 4080;

function showError(err, port) {
  if ('EACCES' === err.code) {
    console.error(err);
    console.warn("You do not have permission to use '" + port + "'.");
    console.warn("You can probably fix that by running as Administrator or root.");
  }
  else if ('EADDRINUSE' === err.code) {
    console.warn("Another server is already running on '" + port + "'.");
    console.warn("You can probably fix that by rebooting your comupter (or stopping it if you know what it is).");
  }
}

function createInsecureServer(port, pubdir, opts) {
  return new PromiseA(function (resolve) {
    var server = http.createServer();

    server.on('error', function (err) {
      if (opts.errorInsecurePort || opts.manualInsecurePort) {
        showError(err, port);
        process.exit(1);
        return;
      }

      opts.errorInsecurePort = err.toString();

      return createInsecureServer(insecurePortFallback, pubdir, opts).then(resolve);
    });

    server.on('request', require('redirect-https')({
      port: opts.port
    }));

    server.listen(port, function () {
      opts.insecurePort = port;
      resolve();
    });
  });
}

function createServer(port, pubdir, content, opts) {
  return new PromiseA(function (resolve) {
    var server = https.createServer(opts.httpsOptions);
    var app = require('./app');

    var directive = { public: pubdir, content: content, livereload: opts.livereload
      , servername: opts.servername, expressApp: opts.expressApp };
    var redirectApp = require('redirect-https')({
      port: port
    });

    server.on('error', function (err) {
      if (opts.errorPort || opts.manualPort) {
        showError(err, port);
        process.exit(1);
        return;
      }

      opts.errorPort = err.toString();

      return createServer(portFallback, pubdir, content, opts).then(resolve);
    });

    server.listen(port, function () {
      opts.port = port;

      if (opts.livereload) {
        opts.lrPort = opts.lrPort || lrPort;
        var livereload = require('livereload');
        var server2 = livereload.createServer({
          https: opts.httpsOptions
        , port: opts.lrPort
        , exclusions: [ '.hg', '.git', '.svn', 'node_modules' ]
        });

        console.info("[livereload] watching " + pubdir);
        console.warn("WARNING: If CPU usage spikes to 100% it's because too many files are being watched");
        server2.watch(pubdir);
      }

      if ('false' !== opts.insecurePort && httpPort !== opts.insecurePort) {
        return createInsecureServer(opts.insecurePort, pubdir, opts).then(resolve);
      } else {
        opts.insecurePort = opts.port;
        resolve();
      }
    });

    if ('function' === typeof app) {
      app = app(directive);
    } else if ('function' === typeof app.create) {
      app = app.create(directive);
    }

    server.on('request', function (req, res) {
      if (!req.socket.encrypted) {
        redirectApp(req, res);
        return;
      }

      if ('function' === typeof app) {
        app(req, res);
        return;
      }

      res.end('not ready');
    });

    return PromiseA.resolve(app).then(function (_app) {
      app = _app;
    });
  });
}

module.exports.createServer = createServer;

function run() {
  var defaultServername = 'localhost.daplie.com';
  var minimist = require('minimist');
  var argv = minimist(process.argv.slice(2));
  var port = parseInt(argv.p || argv.port || argv._[0], 10) || httpsPort;
  var livereload = argv.livereload;
  var pubdir = path.resolve(argv.d || argv._[1] || process.cwd());
  var content = argv.c;
  var letsencryptHost = argv['letsencrypt-certs'];
  var tls = require('tls');

  if (argv.V || argv.version || argv.v) {
    if (argv.v) {
      console.warn("flag -v is reserved for future use. Use -V or --version for version information.");
    }
    console.info('v' + require('./package.json').version);
    return;
  }

  // letsencrypt
  var httpsOptions = require('localhost.daplie.com-certificates').merge({});
  var secureContext;

  var opts = {
    agreeTos: argv.agreeTos || argv['agree-tos']
  , debug: argv.debug
  , email: argv.email
  , httpsOptions: {
      key: httpsOptions.key
    , cert: httpsOptions.cert
    //, ca: httpsOptions.ca
    }
  , argv: argv
  };
  var peerCa;

  opts.httpsOptions.SNICallback = function (servername, cb) {
    if (!secureContext) {
      secureContext = tls.createSecureContext(opts.httpsOptions);
    }
    cb(null, secureContext);
    return;
  };

  if (letsencryptHost) {
    argv.key = argv.key || '/etc/letsencrypt/live/' + letsencryptHost + '/privkey.pem';
    argv.cert = argv.cert || '/etc/letsencrypt/live/' + letsencryptHost + '/fullchain.pem';
    argv.root = argv.root || argv.chain || '';
    argv.servername = argv.servername || letsencryptHost;
    argv['serve-root'] = argv['serve-root'] || argv['serve-chain'];
    // argv[express-app]
  }

  if (argv['serve-root'] && !argv.root) {
    console.error("You must specify bath --root to use --serve-root");
    return;
  }

  if (argv.key || argv.cert || argv.root) {
    if (!argv.key || !argv.cert) {
      console.error("You must specify bath --key and --cert, and optionally --root (required with serve-root)");
      return;
    }

    if (!Array.isArray(argv.root)) {
      argv.root = [argv.root];
    }

    opts.httpsOptions.key = fs.readFileSync(argv.key);
    opts.httpsOptions.cert = fs.readFileSync(argv.cert);

    // turn multiple-cert pemfile into array of cert strings
    peerCa = argv.root.reduce(function (roots, fullpath) {
      if (!fs.existsSync(fullpath)) {
        return roots;
      }

      return roots.concat(fs.readFileSync(fullpath, 'ascii')
      .split('-----END CERTIFICATE-----')
      .filter(function (ca) {
        return ca.trim();
      }).map(function (ca) {
        return (ca + '-----END CERTIFICATE-----').trim();
      }));
    }, []);

    // TODO * `--verify /path/to/root.pem` require peers to present certificates from said authority
    if (argv.verify) {
      opts.httpsOptions.ca = peerCa;
      opts.httpsOptions.requestCert = true;
      opts.httpsOptions.rejectUnauthorized = true;
    }

    if (argv['serve-root']) {
      content = peerCa.join('\r\n');
    }
  }

  opts.servername = defaultServername;
  if (argv.servername) {
    opts.servername = argv.servername;
  }
  if (argv.p || argv.port || argv._[0]) {
    opts.manualPort = true;
  }
  if (argv.i || argv['insecure-port']) {
    opts.manualInsecurePort = true;
  }
  opts.insecurePort = parseInt(argv.i || argv['insecure-port'], 10)
    || argv.i || argv['insecure-port']
    || httpPort
    ;
  opts.livereload = livereload;

  if (argv['express-app']) {
    opts.expressApp = require(path.resolve(process.cwd(), argv['express-app']));
  }

  return createServer(port, pubdir, content, opts).then(function () {
    var msg;
    var p;
    var httpsUrl;
    var promise;

    // Port
    msg = 'Serving ' + pubdir + ' at ';
    httpsUrl = 'https://' + opts.servername;
    p = opts.port;
    if (httpsPort !== p) {
      httpsUrl += ':' + p;
    }
    console.info('');
    console.info(msg);
    console.info('');
    console.info('\t' + httpsUrl);

    // Insecure Port
    p = '';
    if (httpPort !== p) {
      p = ':' + opts.insecurePort;
    }
    msg = '\thttp://' + opts.servername + p + ' (redirecting to https)';
    console.info(msg);
    console.info('');

    if (!(argv.servername && defaultServername !== argv.servername && !(argv.key && argv.cert))) {
      // ifaces
      opts.ifaces = require('./local-ip.js').find();
      promise = PromiseA.resolve();
    } else {
      console.info("Attempting to resolve external connection for '" + argv.servername + "'");
      try {
        promise = require('./match-ips.js').match(argv.servername, opts);
      } catch(e) {
        console.warn("Upgrade to version 2.x to use automatic certificate issuance for '" + argv.servername + "'");
        promise = PromiseA.resolve();
      }
    }

    return promise.then(function (matchingIps) {
      if (matchingIps) {
        if (!matchingIps.length) {
          console.info("Neither the attached nor external interfaces match '" + argv.servername + "'");
        }
      }
      opts.matchingIps = matchingIps || [];

      if (opts.matchingIps.length) {
        console.info('');
        console.info('External IPs:');
        console.info('');
        opts.matchingIps.forEach(function (ip) {
          if ('IPv4' === ip.family) {
            httpsUrl = 'https://' + ip.address;
            if (httpsPort !== opts.port) {
              httpsUrl += ':' + opts.port;
            }
            console.info('\t' + httpsUrl);
          }
          else {
            httpsUrl = 'https://[' + ip.address + ']';
            if (httpsPort !== opts.port) {
              httpsUrl += ':' + opts.port;
            }
            console.info('\t' + httpsUrl);
          }
        });
      }

      Object.keys(opts.ifaces).forEach(function (iname) {
        var iface = opts.ifaces[iname];

        if (iface.ipv4.length) {
          console.info('');
          console.info(iname + ':');

          httpsUrl = 'https://' + iface.ipv4[0].address;
          if (httpsPort !== opts.port) {
            httpsUrl += ':' + opts.port;
          }
          console.info('\t' + httpsUrl);

          if (iface.ipv6.length) {
            httpsUrl = 'https://[' + iface.ipv6[0].address + ']';
            if (httpsPort !== opts.port) {
              httpsUrl += ':' + opts.port;
            }
            console.info('\t' + httpsUrl);
          }
        }
      });

      console.info('');
    });
  });
}

if (require.main === module) {
  run();
}
