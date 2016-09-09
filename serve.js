#!/usr/bin/env node
'use strict';

var https = require('https');
var http = require('http');
var fs = require('fs');
var path = require('path');

function createInsecureServer(port, pubdir, opts) {
  var server = http.createServer();

  server.on('error', function (err) {
    console.error(err);
    process.exit(1);
  });

  server.on('request', require('redirect-https')({
    port: port
  }));

  server.listen(opts.insecurePort, function () {
    var msg = 'Serving ' + pubdir + ' at http://' + opts.servername;
    var p = server.address().port;
    if (80 !== p) {
      msg += ':' + p;
    }
    console.info(msg);
  });
}

function createServer(port, pubdir, content, opts) {
  var server = https.createServer(opts);
  var app = require('./app');

  var directive = { public: pubdir, content: content, livereload: opts.livereload
    , servername: opts.servername, expressApp: opts.expressApp };
  var livereload = require('livereload');
  var server2 = livereload.createServer({ https: opts });

  server2.watch(pubdir);

  if (opts.insecurePort) {
    createInsecureServer(port, pubdir, opts);
  }

  server.on('error', function (err) {
    console.error(err);
    process.exit(1);
  });

  server.listen(port, function () {
    var msg = 'Serving ' + pubdir + ' at ';
    var httpsUrl = 'https://' + opts.servername;
    var p = server.address().port;
    if (443 !== p) {
      httpsUrl += ':' + p;
    }
    console.info('');
    console.info(msg);
    console.info('');
    console.info('\t' + httpsUrl);
    Object.keys(opts.ifaces).forEach(function (iname) {
      var iface = opts.ifaces[iname];

      if (iface.ipv4.length) {
        console.info('');
        console.info(iname + ':');

        httpsUrl = 'https://' + iface.ipv4[0].address;
        if (443 !== p) {
          httpsUrl += ':' + p;
        }
        console.info('\t' + httpsUrl);

        httpsUrl = 'https://[' + iface.ipv6[0].address + ']';
        if (443 !== p) {
          httpsUrl += ':' + p;
        }
        if (iface.ipv6.length) {
          console.info('\t' + httpsUrl);
        }
      }
    });
    console.info('');
  });

  if ('function' === typeof app) {
    app = app(directive);
  } else if ('function' === typeof app.create) {
    app = app.create(directive);
  }

  return Promise.resolve(app).then(function (app) {
    server.on('request', app);
  });
}

module.exports.createServer = createServer;

function run() {
  var minimist = require('minimist');
  var argv = minimist(process.argv.slice(2));
  var port = argv.p || argv.port || argv._[0] || 8443;
  var livereload = argv.livereload;
  var pubdir = path.resolve(argv.d || argv._[1] || process.cwd());
  var content = argv.c;
  var letsencryptHost = argv['letsencrypt-certs'];
  var tls = require('tls');

  var cert = require('localhost.daplie.com-certificates');
  var opts = {
    ifaces: require('./local-ip.js').find()
  , key: cert.key
  , cert: cert.cert
  //, ca: cert.ca
  , SNICallback: function (servername, cb) {
      cb(null, tls.createSecureContext(opts));
      return;
    }
  };
  var peerCa;

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

    opts.key = fs.readFileSync(argv.key);
    opts.cert = fs.readFileSync(argv.cert);

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
      opts.ca = peerCa;
      opts.requestCert = true;
      opts.rejectUnauthorized = true;
    }

    if (argv['serve-root']) {
      content = peerCa.join('\r\n');
    }
  }

  opts.servername = 'localhost.daplie.com';
  if (argv.servername) {
    opts.servername = argv.servername;
  }
  opts.insecurePort = argv.i || argv['insecure-port'];
  opts.livereload = livereload;

  if (argv['express-app']) {
    opts.expressApp = require(path.resolve(process.cwd(), argv['express-app']));
  }

  createServer(port, pubdir, content, opts);
}

if (require.main === module) {
  run();
}
