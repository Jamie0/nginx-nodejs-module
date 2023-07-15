FROM ubuntu:latest AS builder

ENV NGINX_VERSION=1.25.1

RUN apt-get update && apt-get install -y software-properties-common && add-apt-repository ppa:mmomtchev/libnode-18.x && apt-get update && apt-get install -y ca-certificates curl g++ libssl-dev libpcre3-dev make unzip zlib1g-dev libnode108 libnode-dev 
RUN cd /tmp && curl http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -o nginx-${NGINX_VERSION}.tar.gz && tar -xf nginx-${NGINX_VERSION}.tar.gz && cd nginx-${NGINX_VERSION} && \
	mkdir ext && cd ext && curl https://github.com/Jamie0/nginx-nodejs-module/archive/refs/heads/main.tar.gz? -L -o main.tar.gz && tar -xf main.tar.gz && mv nginx-nodejs-module-main nginx-nodejs-module && cd .. && \
	./configure --add-dynamic-module=./ext/nginx-nodejs-module \
		--prefix=/etc/nginx \
		--sbin-path=/usr/sbin/nginx \
		--modules-path=/usr/lib/nginx/modules \
		--conf-path=/etc/nginx/nginx.conf \
		--error-log-path=/var/log/nginx/error.log \
		--http-log-path=/var/log/nginx/access.log \
		--pid-path=/var/run/nginx.pid \
		--lock-path=/var/run/nginx.lock \
		--http-client-body-temp-path=/var/cache/nginx/client_temp \
		--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
		--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
		--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
		--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
		--with-perl_modules_path=/usr/lib/perl5/vendor_perl \
		--user=nginx \
		--group=nginx \
		--with-compat \
		--with-file-aio \
		--with-threads \
		--with-http_addition_module \
		--with-http_auth_request_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_mp4_module \
		--with-http_random_index_module \
		--with-http_realip_module \
		--with-http_secure_link_module \
		--with-http_slice_module \
		--with-http_ssl_module \
		--with-http_stub_status_module \
		--with-http_sub_module \
		--with-http_v2_module \
		--with-stream \
		--with-stream_realip_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
	&& sleep 1 && cat objs/Makefile && make -j4 && make install

FROM ubuntu:latest 

COPY --from=builder /etc/nginx /etc/nginx
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/lib/nginx /usr/lib/nginx
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /usr/lib/libnode.so.108 /usr/lib/libnode.so.108


RUN apt-get update && apt-get install -y tzdata curl ca-certificates && addgroup --system --gid 101 nginx  && adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos "nginx user" --shell /bin/false --uid 101 nginx && mkdir -p /var/cache/nginx/client_temp && mkdir /var/cache/nginx/proxy_temp && mkdir /var/log/nginx && chown nginx: /var/cache/nginx /var/log/nginx -R


ENTRYPOINT /usr/sbin/nginx

