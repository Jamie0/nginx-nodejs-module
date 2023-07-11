#include <csignal>
#include <cstring>
#include <libplatform/libplatform.h>
#include <node.h>
#include <node_api.h>
#include <env.h>
#include <env-inl.h>
#include <v8.h>
#include <uv.h>

extern "C" {

#include <stdio.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_palloc.h>

#define NGX_CONF_BUFFER 4096

static char ngx_http_nodejs_middleware_start[] = 
	// "require('') \n"
	"function fetch (req, res) { \n"
	"	req._handlers = {};\n"
	"	res.json = function (data) {\n"
	"		res.setHeader('content-type', 'application/json');\n"
	"		res.end(JSON.stringify(data));"
	"	}\n"
	"	res.data = (function (req, res) {\n";

static char ngx_http_nodejs_middleware_end[] = 
	"	})(req, res);\n"
	"	if (typeof res.data == 'function') {\n"
	"		function next () {\n"
	"			if (!res._status)\n"
	"				res.status(404)\n"	
	"			res.end();\n"
	"		}\n"
	"		return res.data(req, res, next);\n"
	"	} else\n"
	"		res.end(res.data);\n"
	"}; fetch";

static char ngx_http_nodejs_bootstrap_require[] = 
	"const publicRequire = require('module').createRequire(process.cwd() + '/');"
	"globalThis.require = publicRequire;"
	"require('vm').runInThisContext(process.argv[1]);";

static char ngx_http_nodejs_bootstrap_isolate[] = 
	"require('vm').runInThisContext(process.argv[1]);";

static char* ngx_http_nodejs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_nodejs_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_nodejs_init (ngx_cycle_t *cycle);

typedef struct ngx_http_nodejs_loc_conf_s {
	ngx_flag_t require;

	ngx_str_t * code;
	v8::Global<v8::Script> script;
	v8::Isolate * isolate;
	v8::Global<v8::Context> context;
	v8::Global<v8::Value> function;

	ngx_event_t timer;
} ngx_http_nodejs_loc_conf_t;

static ngx_command_t ngx_http_nodejs_commands[] = {

	{ ngx_string("nodejs_block"), /* directive */
	  NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS, /* location context and takes
											no arguments*/
	  ngx_http_nodejs, /* configuration setup function */
	  0, /* No offset. Only one context is supported. */
	  0, /* No offset when storing the module configuration on struct. */
	  NULL},

	{ ngx_string("nodejs_allow_require"),
	  NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,

	  ngx_conf_set_flag_slot,
	  NGX_HTTP_LOC_CONF_OFFSET,
	  offsetof(ngx_http_nodejs_loc_conf_t, require),
	  NULL},

	ngx_null_command /* command termination */
};

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
	ngx_http_nodejs_init, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};


}


static void *start_nodejs (ngx_http_nodejs_loc_conf_t *ncf);
static v8::String::Utf8Value run_v8_script (ngx_http_nodejs_loc_conf_t *ncf, ngx_http_request_t *r);

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


extern "C" {


static void* ngx_http_nodejs_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_nodejs_loc_conf_t *lcf;

	lcf = (ngx_http_nodejs_loc_conf_t*) ngx_pcalloc(cf->pool, sizeof(ngx_http_nodejs_loc_conf_t));

	if (lcf == NULL) {
		return NULL;
	}

	lcf->require = NGX_CONF_UNSET_UINT;

	return lcf;
}

static char* ngx_http_nodejs_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
	ngx_http_nodejs_loc_conf_t *prev = (ngx_http_nodejs_loc_conf_t*) parent;
	ngx_http_nodejs_loc_conf_t *next = (ngx_http_nodejs_loc_conf_t*) child;

	prev->code = next->code;

	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_nodejs_handler(ngx_http_request_t *r) {
	r->headers_out.content_type.len = sizeof("text/plain") - 1;
	r->headers_out.content_type.data = (u_char *) "text/plain";

	ngx_http_nodejs_loc_conf_t *ncf = (ngx_http_nodejs_loc_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_nodejs_module);

	r->headers_out.status = NGX_HTTP_OK;

	v8::String::Utf8Value result = run_v8_script(ncf, r);

	return NGX_OK;
}

static ngx_int_t ngx_http_nodejs_conf_read_token(ngx_conf_t *cf, ngx_http_nodejs_loc_conf_t *ncf) {
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
				code = (ngx_str_t*) ngx_pnalloc(cf->pool, sizeof(ngx_str_t));

				if (code == NULL) {
					return NGX_ERROR;
				}

				code->data = (u_char*) ngx_pnalloc(cf->pool, b->pos - start);

				if (code->data == NULL) {
					return NGX_ERROR;
				}

				code->len = b->pos - start;
				ngx_cpystrn(code->data, start, code->len);

				ncf->code = code;

				return NGX_CONF_BLOCK_DONE;
			}
			deep--;
			continue;
		}
	}
}

static char *ngx_http_nodejs(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {

	ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

	clcf = (ngx_http_core_loc_conf_t*) ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

	clcf->handler = ngx_http_nodejs_handler;

	ngx_http_nodejs_loc_conf_t *ncf = (ngx_http_nodejs_loc_conf_t*) ngx_http_conf_get_module_loc_conf(cf, ngx_http_nodejs_module);

	int rc;

	for ( ;; ) {
		rc = ngx_http_nodejs_conf_read_token(cf, ncf);

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
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
				"failed to load nodejs block");

		return (char*) NGX_CONF_ERROR;

	done:

	return NGX_CONF_OK;
}

static std::unique_ptr<node::MultiIsolatePlatform> platform;
static std::unique_ptr<node::InitializationResult> result;
static v8::Local<v8::Context> context;
static std::unique_ptr<node::CommonEnvironmentSetup> setup;


static ngx_int_t ngx_http_nodejs_init (ngx_cycle_t *cycle) {
	// ngx_http_nodejs_loc_conf_t *ncf = (ngx_http_nodejs_loc_conf_t*) ngx_http_cycle_get_module_main_conf(cf, ngx_http_nodejs_module);

	const int argc = 1;
	const char* argv[] = {"node"};

	std::vector<std::string> args(argv, argv + argc);

	std::vector<std::string> exec_args;
	std::vector<std::string> errors;

	result = node::InitializeOncePerProcess(args, {
		node::ProcessInitializationFlags::kNoInitializeV8,
		node::ProcessInitializationFlags::kNoInitializeNodeV8Platform
	  });

	for (const std::string& error : result->errors())
		fprintf(stderr, "%s: %s\n", args[0].c_str(), error.c_str());

	if (result->early_return() != 0) {
		//ngx_log_error(NGX_LOG_EMERG, cf, 0,
		//		"failed to load nodejs");
		return 0;
	}

	platform = node::MultiIsolatePlatform::Create(4);

	v8::V8::InitializePlatform(platform.get());
	// v8::V8::InitializeICU();
	v8::V8::Initialize();

	return 0;
}

}

static void *start_nodejs (ngx_http_nodejs_loc_conf_t *ncf) {
	// ok, let's load in that nodejs script and register it onto the handler 

	int exit_code = 0;

	std::vector<std::string> errors2;

	setup = node::CommonEnvironmentSetup::Create(platform.get(), &errors2, result->args(), result->exec_args(), node::EnvironmentFlags::kOwnsProcessState);

	if (!setup) {
		for (const std::string& err : errors2)
			fprintf(stderr, "%s: %s\n", result->args()[0].c_str(), err.c_str());

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
		ncf->require ? ngx_http_nodejs_bootstrap_require : ngx_http_nodejs_bootstrap_isolate);

	if (loadenv_ret.IsEmpty()) {
		return (char*) NGX_CONF_ERROR;
	}

	exit_code = node::SpinEventLoop(env).FromMaybe(1);

	ncf->context = v8::Global<v8::Context>(isolate, setup->context());
	ncf->isolate = isolate;

	v8::Local<v8::String> source = v8::String::NewFromUtf8(isolate, (char*) ncf->code->data).ToLocalChecked();

	source = v8::String::Concat(isolate, v8::String::NewFromUtf8(isolate, ngx_http_nodejs_middleware_start).ToLocalChecked(), source);
	source = v8::String::Concat(isolate, source, v8::String::NewFromUtf8(isolate, ngx_http_nodejs_middleware_end).ToLocalChecked());

	v8::Local<v8::Script> script = v8::Script::Compile(setup->context(), source).ToLocalChecked();

	ncf->script = v8::Global<v8::Script>(isolate, script);

	v8::Local<v8::Value> result = script->Run(setup->context()).ToLocalChecked();

	if (!result->IsFunction()) {
		return (char*) NGX_CONF_ERROR;
	}

	ncf->function = v8::Global<v8::Value>(isolate, result);


	return NGX_CONF_OK;
}

static v8::Local<v8::Object> get_http_client_request (ngx_http_nodejs_loc_conf_t *ncf, ngx_http_request_t *r, v8::Local<v8::Context> c) {
	v8::Isolate *iso = (v8::Isolate*) ncf->isolate;

	v8::Local<v8::Object> request_data = v8::Object::New(iso);

	request_data->Set(c, v8::String::NewFromUtf8(iso, "method").ToLocalChecked(), v8::String::NewFromUtf8(iso, (std::string { (const char*) r->method_name.data, r->method_name.len }).c_str()).ToLocalChecked()).Check();
	request_data->Set(c, v8::String::NewFromUtf8(iso, "uri").ToLocalChecked(), v8::String::NewFromUtf8(iso, (std::string { (const char*) r->uri.data, r->uri.len + r->args.len }).c_str()).ToLocalChecked()).Check();

	v8::Local<v8::Object> request_data_connection = v8::Object::New(iso);
	request_data_connection->Set(c, v8::String::NewFromUtf8(iso, "remoteAddress").ToLocalChecked(), v8::String::NewFromUtf8(iso, (std::string { (const char*) r->connection->addr_text.data, r->connection->addr_text.len }).c_str()).ToLocalChecked()).Check();
	request_data->Set(c, v8::String::NewFromUtf8(iso, "connection").ToLocalChecked(), request_data_connection).Check();

	v8::Local<v8::Object> headers = v8::Object::New(iso);

	ngx_list_part_t *part = &r->headers_in.headers.part;
	ngx_table_elt_t *header = (ngx_table_elt_t*) part->elts;

	for (ngx_uint_t i = 0;; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = (ngx_list_part_t*) part->next;
			header = (ngx_table_elt_t*) part->nelts;
			i = 0;
		}

		headers->Set(c,
			v8::String::NewFromUtf8(iso, (std::string { (const char*) header[i].key.data, header[i].key.len }).c_str()).ToLocalChecked(),
			v8::String::NewFromUtf8(iso, (std::string { (const char*) header[i].value.data, header[i].value.len }).c_str()).ToLocalChecked()
		).Check();
	}

	request_data->Set(c, v8::String::NewFromUtf8(iso, "headers").ToLocalChecked(), headers).Check();

	return request_data;

}

static ngx_http_request_t* get_request_from_nodejs (const v8::FunctionCallbackInfo<v8::Value>& args) {
	v8::Local<v8::External> handle = args.This()->Get(
		args.GetIsolate()->GetCurrentContext(),
		v8::String::NewFromUtf8(args.GetIsolate(), "_ngx").ToLocalChecked()
	).ToLocalChecked().As<v8::External>();

	return (ngx_http_request_t*) handle->Value();
}

static void* nodejs_server_response_status (const v8::FunctionCallbackInfo<v8::Value>& args) {
	ngx_http_request_t *r = get_request_from_nodejs(args);

	v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
	v8::Isolate *isolate = args.GetIsolate();

	uint u;
	if (args[0]->Uint32Value(context).To(&u)) {
		r->headers_out.status = u;
		args.This()->Set(context, v8::String::NewFromUtf8(isolate, "_status").ToLocalChecked(), v8::Number::New(isolate, u)).Check();
	}


	args.GetReturnValue().Set(args.This());

	return (void*) &args;
}

static void* nodejs_server_response_write_head (const v8::FunctionCallbackInfo<v8::Value>& args) {
	ngx_http_request_t *r = get_request_from_nodejs(args);

	v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
	v8::Isolate *isolate = args.GetIsolate();

	uint u;
	if (args[0]->Uint32Value(context).To(&u)) {
		r->headers_out.status = u;
		args.This()->Set(context, v8::String::NewFromUtf8(isolate, "_status").ToLocalChecked(), v8::Number::New(isolate, u)).Check();
	}

	// todo: set headers from args[1]

	ngx_http_send_header(r);

	args.This()->Set(context, v8::String::NewFromUtf8(isolate, "headersSent").ToLocalChecked(), v8::Boolean::New(isolate, 1)).Check();

	args.GetReturnValue().Set(args.This());

	return (void*) &args;
}

static void* nodejs_server_response_end (const v8::FunctionCallbackInfo<v8::Value>& args) {
	ngx_http_request_t *r = get_request_from_nodejs(args);

	v8::Local<v8::Context> context = args.GetIsolate()->GetCurrentContext();
	v8::Isolate *isolate = args.GetIsolate();


	r->headers_out.content_length_n = 0;

	if (args.Length()) {
		std::string data = *v8::String::Utf8Value(args.GetIsolate(), args[0]);
		r->headers_out.content_length_n = data.length();
	}

	v8::Local<v8::Boolean> headersSent = args.This()->Get(context, v8::String::NewFromUtf8(isolate, "headersSent").ToLocalChecked()).ToLocalChecked()->ToBoolean(isolate);

	if (!headersSent->Value()) {
		ngx_http_send_header(r);
	}

	// ok, now we can write the data
	if (r->headers_out.content_length_n > 0) {

		ngx_buf_t *b;
		ngx_chain_t out;
		std::string data = *v8::String::Utf8Value(args.GetIsolate(), args[0]);

		u_char *body = (u_char*) ngx_pnalloc(r->pool, r->headers_out.content_length_n + 1);

		ngx_cpystrn(
			body,
			(u_char*) data.c_str(),
			r->headers_out.content_length_n + 1
		);

		b = (ngx_buf_t*)  ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

		out.buf = b;
		out.next = NULL; 

		b->pos = body; 
		b->last = body + r->headers_out.content_length_n; 
		b->memory = 1; 
		b->last_buf = 1;

		ngx_http_output_filter(r, &out);
	}

	args.GetReturnValue().Set(args.This());

	return (void*) &args;
}

static void* nodejs_server_response_set_header (const v8::FunctionCallbackInfo<v8::Value>& args) {
	v8::HandleScope scope(args.GetIsolate());

	ngx_http_request_t *r = get_request_from_nodejs(args);

	std::string header_s = *v8::String::Utf8Value(args.GetIsolate(), args[0]);
	std::string value_s = *v8::String::Utf8Value(args.GetIsolate(), args[1]);

	// ok, we need ensure these strings will stay on the ngx heap 

	u_char *header = (u_char*) ngx_pnalloc(r->pool, header_s.length() + 1);
	ngx_cpystrn(header, (u_char*) header_s.c_str(), header_s.length() + 1);

	u_char *value = (u_char*) ngx_pnalloc(r->pool, value_s.length() + 1);
	ngx_cpystrn(value, (u_char*) value_s.c_str(), value_s.length() + 1);

	if (strcasecmp((char*) header, "content-type") == 0) {
		r->headers_out.content_type.data = value;
		r->headers_out.content_type.len = strlen((char*) value);
	} else if (strcasecmp((char*) header, "content-length") == 0) {
		r->headers_out.content_length_n = (uint32_t) args[1]->Uint32Value(args.GetIsolate()->GetCurrentContext()).ToChecked();

	} else if (strcasecmp((char*) header, "location") == 0) {
		r->headers_out.location = (ngx_table_elt_t*) ngx_list_push(&r->headers_out.headers);
		r->headers_out.location->value.data = value;
		r->headers_out.location->value.len = strlen((char*) value);
		ngx_str_set(&r->headers_out.location->key, header);
	} else if (strcasecmp((char*) header, "server") == 0) {
		r->headers_out.server = (ngx_table_elt_t*) ngx_list_push(&r->headers_out.headers);
		r->headers_out.server->value.data = value;
		r->headers_out.server->value.len = strlen((char*) value);
		ngx_str_set(&r->headers_out.server->key, header);
	} else if (strcasecmp((char*) header, "refresh") == 0) {
		r->headers_out.refresh = (ngx_table_elt_t*) ngx_list_push(&r->headers_out.headers);
		r->headers_out.refresh->value.data = value;
		r->headers_out.refresh->value.len = strlen((char*) value);
		ngx_str_set(&r->headers_out.refresh->key, header);
	} else if (strcasecmp((char*) header, "cache-control") == 0) {
		r->headers_out.cache_control = (ngx_table_elt_t*) ngx_list_push(&r->headers_out.headers);
		r->headers_out.cache_control->value.data = value;
		r->headers_out.cache_control->value.len = strlen((char*) value);
		ngx_str_set(&r->headers_out.cache_control->key, header);
	} else if (strlen((char*) header) > 0) {
		ngx_table_elt_t* header_r = (ngx_table_elt_t*) ngx_list_push(&r->headers_out.headers);

		header_r->key.data = header;
		header_r->key.len = strlen((char*) header);

		header_r->value.data = value;
		header_r->value.len = strlen((char*) value);
	}

	args.GetReturnValue().Set(args.This());

	return (void*) &args;
}

static v8::Local<v8::Object> get_http_server_response (ngx_http_nodejs_loc_conf_t *ncf, ngx_http_request_t *r, v8::Local<v8::Context> c) {
	v8::Isolate *iso = (v8::Isolate*) ncf->isolate;

	v8::Local<v8::Object> response_object = v8::Object::New(iso);

	response_object->Set(c, v8::String::NewFromUtf8(iso, "_ngx").ToLocalChecked(), v8::External::New(iso, (void *) r)).Check();

	response_object->Set(
		c, v8::String::NewFromUtf8(iso, "status").ToLocalChecked(),
		v8::FunctionTemplate::New(iso, (v8::FunctionCallback) &nodejs_server_response_status)->GetFunction(c).ToLocalChecked()
	).Check();

	response_object->Set(
		c, v8::String::NewFromUtf8(iso, "setHeader").ToLocalChecked(),
		v8::FunctionTemplate::New(iso, (v8::FunctionCallback) &nodejs_server_response_set_header)->GetFunction(c).ToLocalChecked()
	).Check();

	response_object->Set(
		c, v8::String::NewFromUtf8(iso, "writeHead").ToLocalChecked(),
		v8::FunctionTemplate::New(iso, (v8::FunctionCallback) &nodejs_server_response_write_head)->GetFunction(c).ToLocalChecked()
	).Check();

	response_object->Set(
		c, v8::String::NewFromUtf8(iso, "end").ToLocalChecked(),
		v8::FunctionTemplate::New(iso, (v8::FunctionCallback) &nodejs_server_response_end)->GetFunction(c).ToLocalChecked()
	).Check();

	return response_object;
}


static int schedule_event_loop (ngx_http_request_t *r);

static void do_event_loop (ngx_event_t *e) {
	ngx_http_request_t *r = (ngx_http_request_t*) e->data;

	ngx_http_nodejs_loc_conf_t *ncf = (ngx_http_nodejs_loc_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_nodejs_module);

	v8::Isolate *isolate = (v8::Isolate*) ncf->isolate;
	v8::Locker locker(isolate);
	v8::HandleScope handle_scope(isolate);

	v8::Isolate::Scope isolate_scope(isolate);

	{
		v8::SealHandleScope seal(isolate);

		isolate->PerformMicrotaskCheckpoint();
		platform->FlushForegroundTasks(isolate);
		platform->DrainTasks(isolate);

		if (!uv_loop_alive(setup->event_loop())) {
			return;
		}

		if (uv_run(setup->event_loop(), UV_RUN_NOWAIT)) 
			schedule_event_loop(r);
	}
}

static int schedule_event_loop (ngx_http_request_t *r) {
	if (!uv_loop_alive(setup->event_loop())) {
		return -1;
	}	

	ngx_http_nodejs_loc_conf_t *ncf = (ngx_http_nodejs_loc_conf_t*) ngx_http_get_module_loc_conf(r, ngx_http_nodejs_module);

	if (!ncf->timer.timer_set) {
		ncf->timer.handler = do_event_loop;
		ncf->timer.data = r;
		ncf->timer.log = r->connection->log;
		ngx_add_timer(&ncf->timer, 5);
	}

	return 0;
}

static v8::String::Utf8Value run_v8_script (ngx_http_nodejs_loc_conf_t *ncf, ngx_http_request_t *r) {
	{
		if (ncf->isolate == NULL) {
			start_nodejs(ncf);
		}

		v8::Isolate *isolate = (v8::Isolate*) ncf->isolate;

		isolate->SetMicrotasksPolicy(v8::MicrotasksPolicy::kAuto);

		v8::TryCatch tryCatch(isolate);

		v8::Locker locker(isolate);
		v8::HandleScope handle_scope(isolate);

		v8::Local<v8::Context> context = v8::Local<v8::Context>::New(isolate, ncf->context);

		v8::Context::Scope context_scope(context);
		v8::Isolate::Scope isolate_scope(isolate);

		v8::Local<v8::Value> function = v8::Local<v8::Value>::New(isolate, ncf->function);
		v8::Local<v8::Object> function_object = function->ToObject(context).ToLocalChecked();

		v8::Local<v8::Object> request_data = get_http_client_request(ncf, r, context);
		v8::Local<v8::Object> response_object = get_http_server_response(ncf, r, context);

		v8::Local<v8::Value> argv[] = { request_data, response_object };

		v8::Local<v8::Value> result = function_object->CallAsFunction(context, context->Global(), 2, argv).ToLocalChecked();

		if (result.IsEmpty()) {
			return v8::String::Utf8Value (isolate, tryCatch.Exception());
		}

		if (result->IsPromise() || uv_loop_alive(setup->event_loop())) {
			r->count++;

			schedule_event_loop(r);
		}

		return v8::String::Utf8Value (isolate, result);
	}
}