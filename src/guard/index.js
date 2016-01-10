'use strict'

/**
 * node-guard
 * Copyright(c) 2016-2016 Harminder Virk
 * MIT Licensed
*/

let guard = exports = module.exports = {}
const ieRegex = /msie\s*(\d+)/i
const allowedOptions = ['DENY', 'ALLOW-FROM', 'SAMEORIGIN']

/**
 * @description adds frame options to the response headr
 * @method addFrameOptions
 * @param  {Object}        res
 * @param  {String}        value
 * @public
 */
guard.addFrameOptions = function (res, value) {
  if (!value) {
    return
  }

  const xValues = value.split(' ')
  let header = xValues[0].trim().toUpperCase()
  const headerValues = xValues[1]

  if (typeof (header) !== 'string' || allowedOptions.indexOf(header) === -1) {
    throw new Error('X-Frame accepts a string within DENY, ALLOW-FROM or SAMEORIGIN')
  }

  if (header === 'ALLOW-FROM') {
    if (typeof (headerValues) !== 'string') {
      throw new Error('Specify a value next to ALLOW-FROM using a space')
    }
    header = `${header} ${headerValues}`
  }
  res.setHeader('X-Frame-Options', header)
}

/**
 * @description adds nosniff option to X-Content-Type-Options
 * header when enabled
 * @method addNoSniff
 * @param  {Object}   res
 * @param  {Boolean}   nosniff
 */
guard.addNoSniff = function (res, nosniff) {
  if (!nosniff) {
    return
  }
  res.setHeader('X-Content-Type-Options', 'nosniff')
}

/**
 * @description adds noopen option to X-Download-Options
 * header when enabled
 * @method addNoOpen
 * @param  {Object}   res
 * @param  {Boolean}   noopen
 */
guard.addNoOpen = function (res, noopen) {
  if (!noopen) {
    return
  }
  res.setHeader('X-Download-Options', 'noopen')
}

/**
 * @description sets up X-XSS-Protection header
 * based upon active browser and actively
 * disabled old versions of ie.
 * @method addXssFilter
 * @param  {Object}     req
 * @param  {Object}     res
 * @param  {Object}     options
 */
guard.addXssFilter = function (req, res, options) {
  /**
   * if not enabled, do not add any headers
   */
  if (!options || !options.enabled) {
    return
  }

  /**
   * if enabled and ie is also enabled, than set it to
   * 1 mode block
   */
  if (options.enableOnOldIE) {
    return res.setHeader('X-XSS-Protection', '1; mode=block')
  }

  const matches = ieRegex.exec(req.headers['user-agent'])

  /**
   * if user is not on ie or able to parse user agent
   * properly than set it to 1 mode block
   */
  if (!matches || (parseFloat(matches[1]) >= 9)) {
    return res.setHeader('X-XSS-Protection', '1; mode=block')
  }

  /**
   * otherwise set it to 0
   */
  res.setHeader('X-XSS-Protection', '0')
}
