serve-https
===========

A simple HTTPS static file server with valid TLS (SSL) certs.

Comes bundled a valid certificate for localhost.daplie.com,
which is great for testing and development, and you can specify your own.

Also great for testing ACME certs from letsencrypt.org.

Install
-------

```bash
npm install --global serve-https
serve-https
```

```
Serving /Users/foo/ at https://localhost.daplie.com:8443
```

Usage
-----

Examples:

```
node serve.js --servername jane.daplie.me --agree-tos --email jane@example.com --tunnel
```

* `-p <port>` - i.e. `sudo serve-https -p 443` (defaults to 80+443 or 8443)
* `-d <dirpath>` - i.e. `serve-https -d /tmp/` (defaults to `pwd`)
* `-c <content>` - i.e. `server-https -c 'Hello, World! '` (defaults to directory index)
* `--express-app <path>` - path to a file the exports an express-style app (`function (req, res, next) { ... }`)
* `--livereload` - inject livereload into all html pages (see also: [fswatch](http://stackoverflow.com/a/13807906/151312)), but be careful if `<dirpath>` has thousands of files it will spike your CPU usage to 100%

* `--email <email>` - email to use for Let's Encrypt, Daplie DNS, Daplie Tunnel
* `--agree-tos` - agree to terms for Let's Encrypt, Daplie DNS
* `--servername <servername>` - use `<servername>` instead of `localhost.daplie.com`
* `--tunnel` - make world-visible (must use `--servername`)

Specifying a custom HTTPS certificate:

* `--key /path/to/privkey.pem` specifies the server private key
* `--cert /path/to/fullchain.pem` specifies the bundle of server certificate and all intermediate certificates
* `--root /path/to/root.pem` specifies the certificate authority(ies)

Note: `--root` may specify single cert or a bundle, and may be used multiple times like so:

```
--root /path/to/primary-root.pem --root /path/to/cross-root.pem
```

Other options:

* `--serve-root true` alias for `-c` with the contents of root.pem
* `--servername example.com` changes the servername logged to the console
* `--letsencrypt-certs example.com` sets and key, fullchain, and root to standard letsencrypt locations

Examples
--------

```bash
serve-https -p 1443 -c 'Hello from 1443' &
serve-https -p 2443 -c 'Hello from 2443' &
serve-https -p 3443 -d /tmp &

curl https://localhost.daplie.com:1443
> Hello from 1443

curl --insecure https://localhost:2443
> Hello from 2443

curl https://localhost.daplie.com:3443
> [html index listing of /tmp]
```

And if you tested <http://localhost.daplie.com:3443> in a browser,
it would redirect to <https://localhost.daplie.com:3443> (on the same port).

(in curl it would just show an error message)

### Testing ACME Let's Encrypt certs

In case you didn't know, you can get free https certificates from
[letsencrypt.org](https://letsencrypt.org)
(ACME letsencrypt)
and even a free subdomain from <https://freedns.afraid.org>.

If you want to quickly test the certificates you installed,
you can do so like this:

```bash
sudo serve-https -p 8443 \
  --letsencrypt-certs test.mooo.com \
  --serve-root true
```

which is equilavent to

```bash
sudo serve-https -p 8443 \
  --servername test.mooo.com
  --key /etc/letsencrypt/live/test.mooo.com/privkey.pem \
  --cert /etc/letsencrypt/live/test.mooo.com/fullchain.pem \
  --root /etc/letsencrypt/live/test.mooo.com/root.pem \
  -c "$(cat 'sudo /etc/letsencrypt/live/test.mooo.com/root.pem')"
```

and can be tested like so

```bash
curl --insecure https://test.mooo.com:8443 > ./root.pem
curl https://test.mooo.com:8843 --cacert ./root.pem
```

* [QuickStart Guide for Let's Encrypt](https://coolaj86.com/articles/lets-encrypt-on-raspberry-pi/)
* [QuickStart Guide for FreeDNS](https://coolaj86.com/articles/free-dns-hosting-with-freedns-afraid-org.html)
