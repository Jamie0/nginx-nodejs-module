#!/bin/bash

if [[ "$libnode_path" != "" ]]; then
	SYSTEM_NODE=1

	nodejs_include="/usr/include/nodejs/deps/uv/include /usr/include/nodejs/deps/v8/include /usr/include/nodejs/src"
fi

if [[ $SYSTEM_NODE -eq 0 ]]; then
	echo 'Could not find system nodejs-libs (libnode.so) - linking from source'

	nodejs_dir="$ngx_addon_dir/ext/node-v18.16.1"

	if [[ ! -d "$nodejs_dir/out/Release" ]]; then

		if [[ "$NUMCPUS" -eq "" ]]; then
			NUMCPUS=`nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo Failed to detect number of CPUs, please export NUMCPUS=n || echo 1`
		fi

		mkdir -p ext
		pushd $nodejs_dir

		wget "https://nodejs.org/dist/v18.16.1/node-v18.16.1.tar.gz" && tar -xf ./nodejs-18.16.1.tar.gz && rm ./nodejs-18.16.1.tar.gz || (echo Failed to download node && exit 1)

		popd

		if [[ ! -d "$nodejs_dir/tools" ]]; then
			echo Configuring Node
			./configure --enable-static
		fi

		echo Making node
		make -j$NUMCPUS
	else 
		echo libnode was found locally
	fi

	nodejs_link_version=node.108

	nodejs_include="\
	    $ngx_addon_dir/ext/node-v18.16.1/deps/uv/include \
	    $ngx_addon_dir/ext/node-v18.16.1/deps/v8/include \
	    $ngx_addon_dir/ext/node-v18.16.1/src"

	libnode_path=${ngx_addon_dir}/ext/node-v18.16.1/out/Release
fi