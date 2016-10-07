'use strict';

module.exports = function (opts) {
  var finalhandler = require('finalhandler');
  var serveStatic = require('serve-static');
  var serveIndex = require('serve-index');
  var serve = serveStatic(opts.public);
  var index = serveIndex(opts.public);
  var content = opts.content;

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

  return function (req, res) {
    if (content && '/' === req.url) {
      // res.setHeader('Content-Type', 'application/octet-stream');
      res.end(content);
      return;
    }
    var done = finalhandler(req, res);

    if (opts.livereload) {
      res.__my_livereload = '<script src="//'
        + (res.getHeader('Host') || opts.servername).split(':')[0]
        + ':35729/livereload.js?snipver=1"></script>';
      res.__my_addLen = res.__my_livereload.length;

      // TODO modify prototype instead of each instance?
      res.__write = res.write;
      res.write = _reloadWrite;
    }

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
