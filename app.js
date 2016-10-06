'use strict';

module.exports = function (opts) {
  var finalhandler = require('finalhandler');
  var serveStatic = require('serve-static');
  var serveIndex = require('serve-index');
  var serve = serveStatic(opts.public);
  var index = serveIndex(opts.public);
  var content = opts.content;

  return function (req, res) {
    if (content && '/' === req.url) {
      // res.setHeader('Content-Type', 'application/octet-stream');
      res.end(content);
      return;
    }
    var done = finalhandler(req, res);
    var livereload = '';
    var addLen = 0;

    if (opts.livereload) {
      livereload = '<script src="//'
        + (res.getHeader('Host') || opts.servername).split(':')[0]
        + ':' + opts.lrPort + '/livereload.js?snipver=1"></script>';
      addLen = livereload.length;
    }

    res.__write = res.write;
    res.write = function (data, enc, cb) {
      if (this.headersSent) {
        this.__write(data, enc, cb);
        return;
      }

      if (!/html/i.test(this.getHeader('Content-Type'))) {
        this.__write(data, enc, cb);
        return;
      }

      if (this.getHeader('Content-Length')) {
        this.setHeader('Content-Length', this.getHeader('Content-Length') + addLen);
      }

      this.__write(livereload);
      this.__write(data, enc, cb);
    };

    function serveStatic() {
      serve(req, res, function (err) {
        if (err) { return done(err); }
        index(req, res, done);
      });
    }

    if (opts.expressApp) {
      opts.expressApp(req, res, serveStatic);
    }
    else {
      serveStatic();
    }
  };
};
