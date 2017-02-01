'use strict';

module.exports = function (opts) {
  var finalhandler = require('finalhandler');
  var serveStatic = require('serve-static');
  var serveIndex = require('serve-index');

  var hostsMap = {};
  var pathsMap = {};
  var content = opts.content;
  var server;

  function addServer(hostname) {
    console.log('add server:', hostname);

    if (hostsMap[hostname]) {
      return hostsMap[hostname];
    }

    var tmp = { };

    opts.sites.forEach(function (site) {
      if (hostname !== site.name) {
        return;
      }

      console.log('add server for reals', tmp);

      site.path = site.path || site.paths[0] || '.';

      if (!pathsMap[site.path]) {
        pathsMap[site.path] = {
          serve: serveStatic(site.path)
        // TODO option for dotfiles
        , index: serveIndex(site.path)
        };
      }

      hostsMap[hostname] = {
        serve: pathsMap[site.path].serve
      , index: pathsMap[site.path].index
      , app: site.app
      };

    });

  }

  function _reloadWrite(data, enc, cb) {
    /*jshint validthis: true */
    if (this.headersSent) {
      this.__write(data, enc, cb);
      return;
    }

    if (!/html/i.test(this.getHeader('Content-Type'))) {
      this.__write(data, enc, cb);
      return;
    }

    if (this.getHeader('Content-Length')) {
      this.setHeader('Content-Length', this.getHeader('Content-Length') + this.__my_addLen);
    }

    this.__write(this.__my_livereload);
    this.__write(data, enc, cb);
  }


  opts.servername = opts.servername || opts.sites[0].name;

  addServer(opts.sites[0].name);

  return function (req, res) {
    if (content && '/' === req.url) {
      // res.setHeader('Content-Type', 'application/octet-stream');
      res.end(content);
      return;
    }
    var done = finalhandler(req, res);
    var host = req.headers.host;
    var hostname = (host||'').split(':')[0] || opts.servername;

    function serveStatic(server) {
      if (server.expressApp) {
        server.expressApp(req, res, serveStatic);
        return;
      }

      server.serve(req, res, function (err) {
        if (err) { return done(err); }
        server.index(req, res, done);
      });
    }

    if (opts.livereload) {
      res.__my_livereload = '<script src="//'
        + (host || opts.servername).split(':')[0]
        + ':35729/livereload.js?snipver=1"></script>';
      res.__my_addLen = res.__my_livereload.length;

      // TODO modify prototype instead of each instance?
      res.__write = res.write;
      res.write = _reloadWrite;
    }

    console.log('hostname:', hostname);

    addServer(hostname);
    server = hostsMap[hostname] || hostsMap[opts.sites[0].name];
    serveStatic(server);

  };
};
