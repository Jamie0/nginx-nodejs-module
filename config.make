sed=sed

echo $OSTYPE | grep darwin -q && export sed=gsed

# Because, of course, auto/module runs after config.make, and there's no other nginx build hook where we can run code :/ 

fix() {
	sleep 0.1

	$sed '/ngx_http_nodejs_module.cpp/{n;s/CFLAGS)/CFLAGS) -std=c++17/}' $NGX_MAKEFILE -i
}

fix&
