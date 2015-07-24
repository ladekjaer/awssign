# awssign
Creates nessasary HTTP headers for request to the AWS API. Uses AWS4-HMAC-SHA256.

Given the options object to be passed to https.request(options, callback) [awssign](https://github.com/ladekjaer/awssign) ands the following headers x-amz-date, x-amz-content-sha256 and authorization.

Credentials and region will be looked for in environment variables and secondary in ~/.aws/credentials and ~/.aws.config. For IAM Role see below.

## Install
```
npm install awssign
```

## Usage
``` js
var https = require('https')
var crypto = require('crypto')
var fs = require('fs')
var awssign = require('awssign')

var file = fs.readFileSync('path-to-file.txt')
var filehash = crypto.createHash('sha256').update(file).digest('hex')

var options = {
	hostname: 'mybucket.s3.amazonaws.com',
	port: 443,
	path: '/myfolder/file.txt',
	method: 'PUT',
	headers: {
		'Content-Type': 'text/plain; charset=utf8',
		'Content-Length': file.length
	}
}

awssign.signature(options, filehash) // This and nessary headers to the options object.

var req = https.request(options, function(res) {
	if (res.statusCode !== 200) {
		res.setEncoding('utf8')
		var body = ''
		res.on('data', function(chunk) { body += chunk })
		res.on('end', function() { console.error('HTTP response: %s', body)})
	}
})
req.on('error', function(err) {
	console.error('ERROR: %s', err)
})
req.write(file)
req.end()
```

If the HTTP request to AWS has no body call awssign.singature with only the options argument.

## More options
Credentials and region can be overwritten with
``` js
awssign.setup(aws_key, aws_secret, aws_region)
```
Pass null for values not to be overridden.

### IAM Role
If awssign is used from an EC2 instance with an IAM Role is can get the credentials from there. Just remember to set the IAM role and the S3 region.
``` js
awssign.setup(null, null, region)

awssign.iamrole(iam_role, function(err, res) {
    awssign.signature(options, bodyhash)
    var req = https.request(options, function(res) {
        ...
    })
})
```

## License

MIT
