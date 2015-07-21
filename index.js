var crypto = require('crypto')
var util = require('util')
var ini = require('ini')
var fs = require('fs')
var path = require('path')

var SIGN_VERSION = 'AWS4-HMAC-SHA256'
var HOME = process.env.HOME
var aws_key = process.env.AWS_ACCESS_KEY_ID
var aws_secret = process.env.AWS_SECRET_ACCESS_KEY
var aws_region = process.env.AWS_DEFAULT_REGION

if (!aws_key || !aws_secret) {
    var credentials = path.join(HOME, '.aws/credentials')
    credentials = fs.readFileSync(credentials, {encoding: 'utf8'})
    credentials = ini.parse(credentials)
    aws_key = aws_key ? aws_key : credentials.default.aws_access_key_id
    aws_secret = aws_secret ? aws_secret : credentials.default.aws_secret_access_key
}

if (!aws_region) {
    var config = path.join(HOME, '.aws/config')
    config = fs.readFileSync(config, {encoding: 'utf8'})
    config = ini.parse(config)
    aws_region = config.default.region
}

module.exports.setup = function(awskey, awssecret, awsregion) {
    aws_key = awskey ? awskey : aws_key
    aws_secret = awssecret ? awssecret : aws_secret
    aws_region = awsregion ? awsregion : aws_region
}

module.exports.signature = function(httpOptions, bodyhash) {
    var date = timeStampISO8601()
    httpOptions.headers['x-amz-date'] = date
    httpOptions.headers['x-amz-content-sha256'] = bodyhash ? bodyhash : emptyStringHash()
    
    var signingHeaders = createSignedHeaders(httpOptions)
    var canonicalRequest = createCanonicalRequest(httpOptions, bodyhash, signingHeaders)
    var stringToSign = createStringToSign(httpOptions, canonicalRequest, date, aws_region)
    var signature = createSignature(httpOptions, stringToSign, date, aws_region)
    var scope = createScope(httpOptions, date, aws_region)

    var auth = util.format('%s Credential=%s/%s,SignedHeaders=%s,Signature=%s', SIGN_VERSION, aws_key, scope, signingHeaders, signature)

    httpOptions.headers.Authorization = auth
}

function timeStampISO8601() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/[:\-]/g, '')
}

function hash(str) {
    return crypto.createHash('sha256').update(str).digest('hex')
}

function emptyStringHash() {
    return hash('')
}

function hmacSha256(key, data, digest) {
    var hmac = crypto.createHmac('sha256', key)
    hmac.update(data)
    if (!digest) return hmac.digest()
    else return hmac.digest(digest)
}

function createSignedHeaders(options) {
    var headers = Object.keys(options.headers).sort(function(a, b) {
        if (a.toLowerCase() > b.toLowerCase()) return 1
        if (a.toLowerCase() < b.toLowerCase()) return -1
        return 0
    })
    var signedHeaders = ''
    var hostIncluded = false
    headers.forEach(function(header) {
        if (signedHeaders !== '') signedHeaders += ';'
        if (!hostIncluded && 'host' < header.toLowerCase()) {
            signedHeaders += 'host;'
            hostIncluded = true
        }
        signedHeaders += header.toLowerCase()
    })
    if (signedHeaders === 'host;') signedHeaders = 'host'
    return signedHeaders
}

function createScope(options, date, region) {
    var shortdate = date.substring(0, 8)
    var host = options.hostname || options.host
    var service = host.match(/([^\.]*)\.amazonaws\.com/)[1]
    var scope = util.format('%s/%s/%s/aws4_request', shortdate, region, service)
    return scope
}

function createCanonicalRequest(options, bodyhash, signingHeaders) {
    var HTTP_VERB = options.method.toUpperCase()

    var canonicalQueryString = '' // THIS MUST BE CORRECTED !!!

    var canonicalRequest = ''
    canonicalRequest += HTTP_VERB + '\n'
    canonicalRequest += encodeURI(options.path) + '\n'
    canonicalRequest += canonicalQueryString + '\n'

    var headers = ''
    var hostIncluded = false
    Object.keys(options.headers).sort(function(a, b) {
        if (a.toLowerCase() > b.toLowerCase()) return 1
        if (a.toLowerCase() < b.toLowerCase()) return -1
        return 0
    }).forEach(function(header) {
        if (!hostIncluded && 'host' < header.toLowerCase()) {
            headers += 'host:' + (options.hostname || options.host).trim() + '\n'
            hostIncluded = true
        }
        headers += header.toLowerCase() + ':' + (options.headers[header] + '').trim() + '\n'
    })
    headers += '\n'

    canonicalRequest += headers
    canonicalRequest += signingHeaders + '\n'
    canonicalRequest += bodyhash

    return canonicalRequest
}

function createStringToSign(options, canonicalRequest, date, region) {
    var scope = createScope(options, date, region)
    var stringToSign = SIGN_VERSION + '\n'
    stringToSign += date + '\n'
    stringToSign += scope + '\n'
    stringToSign += hash(canonicalRequest)
    return stringToSign
}

function createSignature(options, stringToSign, date, region) {
    var shortdate = date.substring(0, 8)
    var REQUESTTYPE = 'aws4_request'
    var host = options.hostname || option.host
    var service = host.match(/([^\.]*)\.amazonaws\.com/)[1]

    var dateKey = hmacSha256('AWS4'+aws_secret, shortdate)
    var dateRegionKey = hmacSha256(dateKey, region)
    var dateRegionServiceKey = hmacSha256(dateRegionKey, service)
    var signingKey = hmacSha256(dateRegionServiceKey, REQUESTTYPE)

    var signature = hmacSha256(signingKey, stringToSign, 'hex')
    return signature
}

