#include "ah.h"
#include "auth.h"

int _EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in)
{
	unsigned char *tmp_buf;
	if ((in == NULL) || (in->digest == NULL))
	{
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,EVP_R_INPUT_NOT_INITIALIZED);
		return 0;
	}
#ifndef OPENSSL_NO_ENGINE
	/* Make sure it's safe to copy a digest context using an ENGINE */
	if (in->engine && !ENGINE_init(in->engine))
	{
		EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,ERR_R_ENGINE_LIB);
		return 0;
	}
#endif

	if (out->digest == in->digest)
	{
		tmp_buf = out->md_data;
		EVP_MD_CTX_set_flags(out,EVP_MD_CTX_FLAG_REUSE);
	}
	else tmp_buf = NULL;
	EVP_MD_CTX_cleanup(out);
	memcpy(out,in,sizeof *out);

	if (in->md_data && out->digest->ctx_size)
	{
		if (tmp_buf)
			out->md_data = tmp_buf;
		else
		{
			out->md_data=OPENSSL_malloc(out->digest->ctx_size);
			if (!out->md_data)
			{
				EVPerr(EVP_F_EVP_MD_CTX_COPY_EX,ERR_R_MALLOC_FAILURE);
				return 0;
			}
		}
		memcpy(out->md_data,in->md_data,out->digest->ctx_size);
	}

	out->update = in->update;

	if (in->pctx)
	{
		out->pctx = EVP_PKEY_CTX_dup(in->pctx);
		if (!out->pctx)
		{
			EVP_MD_CTX_cleanup(out);
			return 0;
		}
	}

	if (out->digest->copy)
		return out->digest->copy(out,in);

	return 1;
}

int _EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
{
#ifndef OPENSSL_FIPS
	/* Don't assume ctx->md_data was cleaned in EVP_Digest_Final,
	 * because sometimes only copies of the context are ever finalised.
	 */
	//TODO digest value is 0x20
	if (ctx->digest && ctx->digest->cleanup
			&& !EVP_MD_CTX_test_flags(ctx,EVP_MD_CTX_FLAG_CLEANED)) {
		ctx->digest->cleanup(ctx);
	}
	if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
			&& !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) 
	{
		OPENSSL_cleanse(ctx->md_data,ctx->digest->ctx_size);
		OPENSSL_free(ctx->md_data);
	}
#endif
	if (ctx->pctx)
		EVP_PKEY_CTX_free(ctx->pctx);
#ifndef OPENSSL_NO_ENGINE
	if(ctx->engine)
		/* The EVP_MD we used belongs to an ENGINE, release the
		 * functional reference we held for this reason. */
		ENGINE_finish(ctx->engine);
#endif
#ifdef OPENSSL_FIPS
	FIPS_md_ctx_cleanup(ctx);
#endif
	memset(ctx,'\0',sizeof *ctx);

	return 1;
}

int _HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
	unsigned int i;
	unsigned char buf[EVP_MAX_MD_SIZE];
#ifdef OPENSSL_FIPS
	if (FIPS_mode() && !ctx->i_ctx.engine)
		return FIPS_hmac_final(ctx, md, len);
#endif

	if (!EVP_DigestFinal_ex(&ctx->md_ctx,buf,&i))
		goto err;
	if (!_EVP_MD_CTX_copy_ex(&ctx->md_ctx,&ctx->o_ctx))
		goto err;
	if (!EVP_DigestUpdate(&ctx->md_ctx,buf,i))
		goto err;
	if (!EVP_DigestFinal_ex(&ctx->md_ctx,md,len))
		goto err;
	return 1;
err:
	return 0;
}

unsigned char* _HMAC(const EVP_MD *evp_md, const void *key, int key_len,
		const unsigned char *d, size_t n, unsigned char *md,
		unsigned int *md_len)
{
	HMAC_CTX c;
	static unsigned char m[EVP_MAX_MD_SIZE];

	if (md == NULL) md=m;
	HMAC_CTX_init(&c);
	if (!HMAC_Init(&c,key,key_len,evp_md))
		goto err;
	if (!HMAC_Update(&c,d,n))
		goto err;
	if (!_HMAC_Final(&c,md,md_len))
		goto err;
	HMAC_CTX_cleanup(&c);
	return md;
err:
	return NULL;
}

static void _hmac_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_md5(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}

static void _hmac_sha1(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_sha1(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
   Not implemented : No RFC
*/
static void _keyed_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
}

static void _keyed_sha1(void* payload, size_t size, unsigned char* result, SA* sa) {
}

static void _hmac_sha256(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_sha256(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
	TODO : Debug for 384, 512
*/
static void _hmac_sha384(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_sha384(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}

static void _hmac_sha512(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_sha512(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}

static void _hmac_ripemd160(void* payload, size_t size, unsigned char* result, SA* sa) {
	uint64_t* auth_key = NULL;
	int auth_key_length = 0;

	if(sa->ipsec_protocol == IP_PROTOCOL_ESP) {
		auth_key = ((SA_ESP*)sa)->auth_key;
		auth_key_length = ((SA_ESP*)sa)->auth_key_length;
	} else if(sa->ipsec_protocol == IP_PROTOCOL_AH) {
		auth_key = ((SA_AH*)sa)->auth_key;
		auth_key_length = ((SA_AH*)sa)->auth_key_length;
	}

	unsigned char* _result = _HMAC(EVP_ripemd160(), auth_key, auth_key_length, payload, size, NULL, NULL);
	memcpy(result, _result, AUTH_DATA_LEN);
}
/*
   Not implemented : No openssl function

	   AES-XCBC-MAC is not directly supported. However, it's very simple to
	   implement as it's based on AES-CBC for which there is support.
*/
static void _aes_xcbc_mac(void* payload, size_t size, unsigned char* result, SA* sa) {
}
/* 
   Not implemented : Only for BSD
*/
static void _tcp_md5(void* payload, size_t size, unsigned char* result, SA* sa) {
}

Authentication authentications[] = {
	{.authenticate = _hmac_md5},
	{.authenticate = _hmac_sha1},
	{.authenticate = _keyed_md5},
	{.authenticate = _keyed_sha1},
	{.authenticate = _hmac_sha256},
	{.authenticate = _hmac_sha384},
	{.authenticate = _hmac_sha512},
	{.authenticate = _hmac_ripemd160},
	{.authenticate = _aes_xcbc_mac},
	{.authenticate = _tcp_md5},
};

Authentication* get_authentication(int algorithm) {
	return &authentications[algorithm - 1];
}

