#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <node.h>
#include <node_api.h>
#include <ngx_config.h>
#include <cstring>
#include "env.h"
#include "env-inl.h"
#include "v8.h"
#include "uv.h"

#define NGX_CONF_BUFFER 4096

#define NODEJS "hello world\r\n"

static char *ngx_http_nodejs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_nodejs_handler(ngx_http_request_t *r);

/**
 * This module provided directive: hello world.
 *
 */
static ngx_command_t ngx_http_nodejs_commands[] = {

	{ ngx_string("nodejs_block"), /* directive */
	  NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS, /* location context and takes
											no arguments*/
	  ngx_http_nodejs, /* configuration setup function */
	  NGX_HTTP_LOC_CONF_OFFSET, /* No offset. Only one context is supported. */
	  0, /* No offset when storing the module configuration on struct. */
	  NULL},

	ngx_null_command /* command termination */
};

/* The hello world string. */
static u_char ngx_nodejs[] = NODEJS;

static void* ngx_http_nodejs_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_nodejs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

/* The module context. */
static ngx_http_module_t ngx_http_nodejs_module_ctx = {
	NULL, /* preconfiguration */
	NULL, /* postconfiguration */

	NULL, /* create main configuration */
	NULL, /* init main configuration */

	NULL, /* create server configuration */
	NULL, /* merge server configuration */

	ngx_http_nodejs_create_loc_conf, /* create location configuration */
	ngx_http_nodejs_merge_loc_conf /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_nodejs_module = {
	NGX_MODULE_V1,
	&ngx_http_nodejs_module_ctx, /* module context */
	ngx_http_nodejs_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	NULL, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};

typedef struct ngx_http_nodejs_loc_conf_s {
	ngx_str_t code;
	void * script;
} ngx_http_nodejs_loc_conf_t;

static void* ngx_http_nodejs_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_nodejs_loc_conf_t *lcf;

	lcf = (ngx_http_nodejs_loc_conf_t*) ngx_pcalloc(cf->pool, sizeof(ngx_http_nodejs_loc_conf_t));

	if (lcf == NULL)
		return NGX_CONF_ERROR;

	return NGX_CONF_OK;
}

static char* ngx_http_nodejs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_nodejs_loc_conf_t *prev = (ngx_http_nodejs_loc_conf_t*) parent;
	ngx_http_nodejs_loc_conf_t *next = (ngx_http_nodejs_loc_conf_t*) child;

	prev->code = next->code;

	return NGX_CONF_OK;
}

// this isn't exported?!
u_char * ngx_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) {
        return dst;
    }

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}

/**
 * Content handler.
 *
 * @param r
 *   Pointer to the request structure. See http_request.h.
 * @return
 *   The status of the response generation.
 */
static ngx_int_t ngx_http_nodejs_handler(ngx_http_request_t *r)
{
	ngx_buf_t *b;
	ngx_chain_t out;

	/* Set the Content-Type header. */
	r->headers_out.content_type.len = sizeof("text/plain") - 1;
	r->headers_out.content_type.data = (u_char *) "text/plain";

	/* Allocate a new buffer for sending out the reply. */
	b = (ngx_buf_t*)  ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

	/* Insertion in the buffer chain. */
	out.buf = b;
	out.next = NULL; /* just one buffer */

	b->pos = ngx_nodejs; /* first position in memory of the data */
	b->last = ngx_nodejs + sizeof(ngx_nodejs) - 1; /* last position in memory of the data */
	b->memory = 1; /* content is in read-only memory */
	b->last_buf = 1; /* there will be no more buffers in the request */

	/* Sending the headers for the reply. */
	r->headers_out.status = NGX_HTTP_OK; /* 200 status code */
	/* Get the content length of the body. */
	r->headers_out.content_length_n = sizeof(ngx_nodejs) - 1;
	ngx_http_send_header(r); /* Send the headers */

	/* Send the body, and return the status code of the output filter chain. */
	return ngx_http_output_filter(r, &out);
} /* ngx_http_nodejs_handler */

ngx_int_t
ngx_http_nodejs_conf_read_token(ngx_conf_t *cf)
{
	u_char      *start, ch;
	off_t        file_size;
	size_t       len;
	ssize_t      n, size;
	ngx_uint_t   start_line;
	ngx_buf_t   *b, *dump;
	ngx_str_t   *code;
	ngx_uint_t deep;
	deep = 0;
   
	cf->args->nelts = 0;
	b = cf->conf_file->buffer;
	dump = cf->conf_file->dump;
	start = b->pos;
	start_line = cf->conf_file->line;

	file_size = ngx_file_size(&cf->conf_file->file.info);

	for ( ;; ) {
		if (b->pos >= b->last) {
			if (cf->conf_file->file.offset >= file_size) {
				if (cf->args->nelts > 0 ) {
					if (cf->conf_file->file.fd == NGX_INVALID_FILE) {
						ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
							"unexpected end of parameter, "
							"expecting \";\"");
						return NGX_ERROR;
					}

					ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
						"unexpected end of file, "
						"expecting \";\" or \"}\"");
					return NGX_ERROR;
				}
				return NGX_CONF_FILE_DONE;
			}
			len = b->pos - start;

			if (len == NGX_CONF_BUFFER) {
				cf->conf_file->line = start_line;
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					"too long parameter, probably "
					"missing terminating \"\" character");
				return NGX_ERROR;
			}

			if (len) {
				ngx_memmove(b->start, start, len);
			}

			size = (ssize_t) (file_size - cf->conf_file->file.offset);

			if (size > b->end - (b->start + len)) {
				size = b->end - (b->start + len);
			}

			n = ngx_read_file(&cf->conf_file->file, b->start + len, size,
				cf->conf_file->file.offset);

			if (n == NGX_ERROR) {
				return NGX_ERROR;
			}
			if (n != size) {
				ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
					ngx_read_file_n " returned "
					"only %z bytes instead of %z",
					n, size);
				return NGX_ERROR;
			}
			b->pos = b->start + len;
			b->last = b->pos + n;

			start = b->start;

			if (dump) {
				dump->last = ngx_cpymem(dump->last, b->pos, size);
			}
		}
		ch = *b->pos++;
		printf("%c\n", (char)ch);
		if (ch == LF) {
			cf->conf_file->line++;
			continue;
		}
		if (ch == '{') {
			deep++;
			continue;
		}
		if (ch == '}') {
			if (deep == 0) {
				code = (ngx_str_t*) ngx_array_push(cf->args);
				if (code == NULL) {
					return NGX_ERROR;
				}
				code->data = (u_char*) ngx_pnalloc(cf->pool, b->pos - 1 - start + 1);
				if (code->data == NULL) {
					return NGX_ERROR;
				}
				code->len = b->pos - 1 - start + 1;
				ngx_cpystrn(code->data, start, code->len);

				printf("%s, %d\n", code->data, (int)code->len);
				return NGX_CONF_BLOCK_DONE;
			}
			deep--;
			continue;
		}
	}
}

std::vector<std::string> create_arg_vec(int argc, const char* const* argv) {
    std::vector<std::string> vec;
    if (argc > 0) {
        vec.reserve(argc);
        for (int i = 0; i < argc; ++i) {
            vec.emplace_back(argv[i]);
        }
    }
    return vec;
}

static char *ngx_http_nodejs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

	/* Install the hello world handler. */
	clcf = (ngx_http_core_loc_conf_t*) ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	/* char* argv[] = {"node", "-e"};

	std::vector<std::string> process_args = create_arg_vec(2, argv);

	std::unique_ptr<node::MultiIsolatePlatform> platform =
		node::MultiIsolatePlatform::Create(4);
	v8::V8::InitializePlatform(platform.get()); */ 

	// ok, let's parse that block

	int rc;

	for ( ;; ) {
		rc = ngx_http_nodejs_conf_read_token(cf);

		if (rc == NGX_ERROR || rc == NGX_CONF_BLOCK_DONE) {
			goto done;
		}

		if (rc == NGX_CONF_FILE_DONE) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"unexpected end of file, expecting \"}\"");
			goto failed;
		}
	}

	failed:
		return (char*) NGX_CONF_ERROR;

	done:

	// ok, let's load in that nodejs script and register it onto the handler 

	const char* argv[] = {"node", "-e",NULL};

	std::vector<std::string> process_args = create_arg_vec(2, argv);
	std::vector<std::string> args { process_args[0] };
	std::vector<std::string> exec_args;
	std::vector<std::string> errors;

	int exit_code = node::InitializeNodeWithArgs(&args, &exec_args, &errors);
	for (const std::string& error : errors)
		fprintf(stderr, "%s: %s\n", args[0].c_str(), error.c_str());

	if (exit_code != 0) {
		return (char*) NGX_CONF_ERROR;
	}

	std::unique_ptr<node::MultiIsolatePlatform> platform = node::MultiIsolatePlatform::Create(4);
	v8::V8::InitializePlatform(platform.get());
	v8::V8::Initialize();


	exit_code = 0;

	std::unique_ptr<node::CommonEnvironmentSetup> setup =
		node::CommonEnvironmentSetup::Create(platform.get(), &errors, args, exec_args, static_cast<node::EnvironmentFlags::Flags>( node::EnvironmentFlags::kDefaultFlags | node::EnvironmentFlags::kNoGlobalSearchPaths ));

	if (!setup) {
		for (const std::string& err : errors)
			fprintf(stderr, "%s: %s\n", args[0].c_str(), err.c_str());
		return (char*) NGX_CONF_ERROR;
	}

	v8::Isolate* isolate = setup->isolate();
	node::Environment* env = setup->env();
	v8::Locker locker(isolate);
	v8::Isolate::Scope isolate_scope(isolate);
	v8::HandleScope handle_scope(isolate);
	v8::Context::Scope context_scope(setup->context());

	v8::MaybeLocal<v8::Value> loadenv_ret = node::LoadEnvironment(
		env,
		"const publicRequire ="
		"  require('module').createRequire(process.cwd() + '/');"
		"globalThis.require = publicRequire;"
		"globalThis.embedVars = { nön_ascıı: '🏳️‍🌈' };"
		"require('vm').runInThisContext(process.argv[1]);");

	if (loadenv_ret.IsEmpty())
		return (char*) NGX_CONF_ERROR;

	exit_code = node::SpinEventLoop(env).FromMaybe(1);

	v8::Local<v8::Context> context = setup->context();

	v8::Local<v8::String> source = v8::String::NewFromUtf8(isolate, (char*) cf->args->elts).ToLocalChecked();
	v8::Local<v8::Script> script = v8::Script::Compile(context, source).ToLocalChecked();

	clcf->handler = ngx_http_nodejs_handler;

	ngx_http_nodejs_loc_conf_t *ncf;
	ncf = (ngx_http_nodejs_loc_conf_t*) conf;

	ncf->script = &script;
	// clcf->options = context;

	return NGX_CONF_OK;
} /* ngx_http_nodejs */