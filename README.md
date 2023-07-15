# nginx-nodejs-module

Run node (v8) scripts directly inside nginx!

## Current Project Status

The project is in the very early stages of development. Currently, running a simple script inside a nginx location block and returning a primitive just about works (and is pleasingly very fast). There is no support _yet_ for consuming the request body, or for complex asynchronous operations that involve I/O. 

If you're better than me at C/C++ and want to contribute, certainly do open a pull request. 

## Example

	load_module /usr/local/nginx/lib/ngx_http_nodejs_module.so;
	events {}

	daemon off;
	http {
		server {
			listen 127.0.0.1:8080;

			location /hello {
				nodejs_block {
					res.setHeader('content-type', 'text/html')
					return 1E6 * Math.random() | 0 
				}
			}

			location /file {
				nodejs_allow_require on;
				nodejs_block {
					const fs = require('fs')

					return async function (req, res, next) {
						res.setHeader('content-type', 'text/html')
						res.end(await fs.promises.readFile('/tmp/test.html'))
					}
				}
			}

			location /world {
				nodejs_block {
					return res.json(req)
				}
			}

			location /async {
				nodejs_block {
					return async function (req, res, next) {
						setTimeout(
							_ => res.json(req),
							100
						)
					}
				}
			}

			location /external {
				nodejs_allow_require on;
				nodejs_block {
					const crypto = require('crypto');
					return function (req, res) {
						res.end(crypto.createHash('md5').update(req.connection.remoteAddress).digest('hex'))
					}
				}
			}
		}
	}

## Building

The module can be built as a dynamic module using the nginx build system, but you will need to fetch some dependencies if you don't have libnode on your system (nvm doesn't include it). If node couldn't be found, it will be compiled during the configuration step. V8 will take some time to compile, so grab a cup of coffee (or three). 


    cd nginx-1.25.1
    ./configure --add-dynamic-module=../nginx-nodejs-module [...]
    make && make install

## Motivation

I thought it would be fun... Hopefully I can learn C++ along the way. 
