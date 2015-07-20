var crypto = require('crypto')
var util = require('util')

var SIGN_VERSION = 'AWS4-HMAC-SHA256'
var AWSKEY = ''
var AWSSECRET = ''
var AWSREGION = ''

module.exports.setup = function(awskey, awssecret, awsregion) {
    AWSKEY = awskey
    AWSSECRET = awssecret
    AWSREGION = awsregion
}

module.exports.signature = function(httpOptions, bodyhash) {
    var date = timeStampISO8601()
    httpOptions.headers['x-amz-date'] = date
    httpOptions.headers['x-amz-content-sha256'] = bodyhash ? bodyhash : emptyStringHash()
    
    var signingHeaders = createSignedHeaders(httpOptions)
    var canonicalRequest = createCanonicalRequest(httpOptions, bodyhash, signingHeaders)
    var stringToSign = createStringToSign(httpOptions, canonicalRequest, date, AWSREGION)
    var signature = createSignature(httpOptions, stringToSign, date, AWSREGION)
    var scope = createScope(httpOptions, date, AWSREGION)

    var auth = util.format('%s Credential=%s/%s,SignedHeaders=%s,Signature=%s', SIGN_VERSION, AWSKEY, scope, signingHeaders, signature)

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

    var dateKey = hmacSha256('AWS4'+AWSSECRET, shortdate)
    var dateRegionKey = hmacSha256(dateKey, region)
    var dateRegionServiceKey = hmacSha256(dateRegionKey, service)
    var signingKey = hmacSha256(dateRegionServiceKey, REQUESTTYPE)

    var signature = hmacSha256(signingKey, stringToSign, 'hex')
    return signature
}

