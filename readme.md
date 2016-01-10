## Node Guard

![](http://i1117.photobucket.com/albums/k594/thetutlage/poppins-1_zpsg867sqyl.png)

![](https://img.shields.io/travis/poppinss/node-guard.svg?style=flat-square)
[![Coverage Status](https://img.shields.io/coveralls/poppinss/node-guard/master.svg?style=flat-square)](https://coveralls.io/github/poppinss/node-guard?branch=master)
[![License](https://img.shields.io/npm/l/node-guard.svg?style=flat-square)](https://opensource.org/licenses/MIT)


General purpose I/O module to add following http headers to keep your webpages securing them from malware attacks. This module can be used with any node http server.

- [X-XSS-Protection](#x-xss-protection)
- [X-Frame-Options](#x-frame-options)
- [X-Content-Type-Options](#x-content-type-options)
- [X-Download-Options](#x-download-options)

## X-XSS-Protection

`X-XSS-Protection` http header saves you from `XSS` attacks. `node-guard` will set up `X-XSS-Protection` header on all modern browsers and will disable it for older versions of IE as they have security vulnerabilities defined here https://technet.microsoft.com/library/security/ms10-002.

```javascript
const http = require('http')
const guard = require('node-guard')
const options = {
  enabled: true,
  enableOnOldIE: false
}

http.createServer(function (req, res) {
  guard.addXssFilter(req, res, options)
  res.end()
}).listen(3000)
```

## X-Frame-Options

`X-Frame-Options` defines whether your webpage can be embedded as an iframe to other website. It can take 3 different values from `ALLOW-FROM`, `DENY` and `SAMEORIGIN`

```javascript
const http = require('http')
const guard = require('node-guard')
const options = 'DENY' // cannot be embedded at all
// or
const options = 'SAMEORIGIN' // only this website
// or
const options = 'ALLOW-FROM http://example.com' // defined uri

http.createServer(function (req, res) {
  guard.addFrameOptions(res, options)
  res.end()
}).listen(3000)
```

## X-Content-Type-Options

`X-Content-Type-Options` disables sniffing from web browsers, where they will try to `sniff` mimetypes. Which means a web browser will execute the javascript file even if the `content-type` of that file is not set to `javascript`. Give it a read https://miki.it/blog/2014/7/8/abusing-jsonp-with-rosetta-flash/


```javascript
const http = require('http')
const guard = require('node-guard')
const options = true // or false

http.createServer(function (req, res) {
  guard.addNoSniff(res, options)
  res.end()
}).listen(3000)
```

## X-Download-Options

IE specific header to stop users from executing html files with the access to your site context. Here is a good read on same https://blogs.msdn.microsoft.com/ie/2008/07/02/ie8-security-part-v-comprehensive-protection/.

```javascript
const http = require('http')
const guard = require('node-guard')
const options = true // or false

http.createServer(function (req, res) {
  guard.addNoOpen(res, options)
  res.end()
}).listen(3000)
```