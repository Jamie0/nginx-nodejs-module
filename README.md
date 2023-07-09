# nginx-nodejs-module

Run node/v8 scripts directly inside nginx!

Why, you ask? Why not!

## Current Project Status

The project is in the very early stages of development. Currently, running a simple script inside a nginx location block and returning a primitive just about works (and is pleasingly very fast). There is no support yet for consuming the request body, or for anything asynchronous. 

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
                    return 1E6 * Math.random() | 0 
                }
            }

            location /world {
                nodejs_block {
                    res.setHeader('content-type', 'application/json')

                    return JSON.stringify({ req })
                }
            }

            location /external {
                nodejs_allow_require on;
                nodejs_block {
                    return require('crypto').createHash('md5').update(req.connection.remoteAddress).digest('hex')
                }
            }
        }
    }

## Building

The module can be built as a dynamic module using the nginx build system, but you will need to fetch some dependencies. V8 will take some time to compile, so be patient. 

    cd nginx-nodejs-module/ext
    wget "https://nodejs.org/dist/v18.16.1/node-v18.16.1.tar.gz" && tar -xf nodejs-18.16.1.tar.gz && rm nodejs-18.16.1.tar.gz

    cd nodejs-18.16.1
    ./configure --enable-static
    make -j8

Finally, build nginx:

    cd nginx-1.25.1
    ./configure --add-dynamic-module=../nginx-nodejs-module [...]
    make && make install

## Motivation

I thought it would be fun... Hopefully I can learn C++ along the way. 
