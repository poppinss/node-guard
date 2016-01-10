'use strict'

/**
 * node-guard
 * Copyright(c) 2016-2016 Harminder Virk
 * MIT Licensed
*/

const guard = require('../src/guard')
const chai = require('chai')
const http = require('http')
const supertest = require('supertest')
const expect = chai.expect
require('co-mocha')

describe('Guard', function() {
  context('X-XSS-Protection', function () {

    it('should not set X-XSS-Protection header when xss is not enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = {}
        guard.addXssFilter(req, res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).not.have.property('X-XSS-Protection'.toLowerCase())
    })

    it('should set X-XSS-Protection header when xss is enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = {
          enabled: true
        }
        guard.addXssFilter(req, res, options)
        res.end()
      })
      const response = yield supertest(server).get('/').set('user-agent', 'Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.133 Mobile Safari/535.19')
      expect(response.headers).to.have.property('X-XSS-Protection'.toLowerCase())
      expect(response.headers['x-xss-protection']).to.equal('1; mode=block')
    })

    it('should set X-XSS-Protection header to 0 when browser is ie', function * () {
      const server = http.createServer(function (req, res) {
        const options = {
          enabled: true
        }
        guard.addXssFilter(req, res, options)
        res.end()
      })
      const response = yield supertest(server).get('/').set('user-agent', 'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0')
      expect(response.headers).to.have.property('X-XSS-Protection'.toLowerCase())
      expect(response.headers['x-xss-protection']).to.equal('0')
    })

    it('should set X-XSS-Protection header to 1 when browser is ie and enable to ie is true', function * () {
      const server = http.createServer(function (req, res) {
        const options = {
          enabled: true,
          enableOnOldIE: true
        }
        guard.addXssFilter(req, res, options)
        res.end()
      })
      const response = yield supertest(server).get('/').set('user-agent', 'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0')
      expect(response.headers).to.have.property('X-XSS-Protection'.toLowerCase())
      expect(response.headers['x-xss-protection']).to.equal('1; mode=block')
    })
  })
  context('X-FRAME-OPTIONS', function () {

    it('should not set X-FRAME-OPTIONS header when iframe is not enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = ''
        guard.addFrameOptions(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).not.have.property('X-FRAME-OPTIONS'.toLowerCase())
    })

    it('should set X-FRAME-OPTIONS header when iframe is from same origin', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'SAMEORIGIN'
        guard.addFrameOptions(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-FRAME-OPTIONS'.toLowerCase())
      expect(response.headers['x-frame-options']).to.equal('SAMEORIGIN')
    })

    it('should set X-FRAME-OPTIONS header when iframe is from same origin and is specified in lower case', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'sameorigin'
        guard.addFrameOptions(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-FRAME-OPTIONS'.toLowerCase())
      expect(response.headers['x-frame-options']).to.equal('SAMEORIGIN')
    })

    it('should set X-FRAME-OPTIONS header when iframe is set to DENY', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'DENY'
        guard.addFrameOptions(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-FRAME-OPTIONS'.toLowerCase())
      expect(response.headers['x-frame-options']).to.equal('DENY')
    })

    it('should throw error when there when define value is not a valid attribute', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'Yes'
        try {
          guard.addFrameOptions(res, options)
          res.end()
        } catch (e) {
          res.writeHead(500)
          res.write(e.message)
          res.end()
        }
      })
      const response = yield supertest(server).get('/').expect(500)
      expect(response.text).to.match(/X-FRAME accepts/i)
    })

    it('should throw error when there is no value defined next to ALLOW-FROM', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'ALLOW-FROM'
        try {
          guard.addFrameOptions(res, options)
          res.end()
        } catch (e) {
          res.writeHead(500)
          res.write(e.message)
          res.end()
        }
      })
      const response = yield supertest(server).get('/').expect(500)
      expect(response.text).to.match(/Specify a value next to ALLOW-FROM/)
    })

    it('should set X-FRAME-OPTIONS header when iframe is set to ALLOW-FROM', function * () {
      const server = http.createServer(function (req, res) {
        const options = 'ALLOW-FROM http://example.com'
        guard.addFrameOptions(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-FRAME-OPTIONS'.toLowerCase())
      expect(response.headers['x-frame-options']).to.equal('ALLOW-FROM http://example.com')
    })
  })

  context('X-Content-Type-Options', function () {
    it('should not set X-Content-Type-Options header when nosniff is not enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = false
        guard.addNoSniff(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).not.have.property('X-Content-Type-Options'.toLowerCase())
    })


    it('should set X-Content-Type-Options header when nosniff is enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = true
        guard.addNoSniff(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-Content-Type-Options'.toLowerCase())
      expect(response.headers['x-content-type-options']).to.equal('nosniff')
    })
  })

  context('X-Download-Options', function () {
    it('should not set X-Download-Options header when noopen is not enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = false
        guard.addNoOpen(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).not.have.property('X-Download-Options'.toLowerCase())
    })


    it('should set X-Download-Options header when noopen is enabled', function * () {
      const server = http.createServer(function (req, res) {
        const options = true
        guard.addNoOpen(res, options)
        res.end()
      })
      const response = yield supertest(server).get('/')
      expect(response.headers).to.have.property('X-Download-Options'.toLowerCase())
      expect(response.headers['x-download-options']).to.equal('noopen')
    })
  })
})