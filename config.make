echo TEST YEE

sed=sed
if [[ "$OSTYPE" == "darwin"* ]]; then
	echo Detected Darwin

	sed=gsed
fi

fix() {
sleep 0.1

$sed '/ngx_http_nodejs_module.cpp/{n;s/CFLAGS)/CFLAGS) -std=c++17/}' $NGX_MAKEFILE -i
echo 'fixed?' $?
}

fix&
