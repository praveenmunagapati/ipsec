#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/aes.h>

#include <net/ether.h>
#include <net/ip.h>
#include <linux/pfkeyv2.h>

#include <auth.h>

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

#define HMAC_MD5_AUTH_DATA_LEN	12
static void _hmac_md5_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_md5(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, t_len);
}

static bool _hmac_md5_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_md5(), key, key_len, source, s_len, NULL, NULL);
	return !memcmp(target, result, t_len);
}

#define HMAC_SHA1_AUTH_DATA_LEN	12
static void _hmac_sha1_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha1(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, t_len);
}

static bool _hmac_sha1_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha1(), key, key_len, source, s_len, NULL, NULL);
	for(int i = 0; i < t_len; i++)
		printf("%x", *(target + i));
	printf("\n");

	for(int i = 0; i < t_len; i++)
		printf("%x", *(result + i));
	printf("\n");
	return !memcmp(target, result, t_len);
}

#define HMAC_SHA256_AUTH_DATA_LEN	12
static void _hmac_sha256_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha256(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, t_len);
}
static bool _hmac_sha256_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha256(), key, key_len, source, s_len, NULL, NULL);
	return !memcmp(target, result, t_len);
}

#define HMAC_SHA384_AUTH_DATA_LEN	28
static void _hmac_sha384_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha384(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, t_len);
}

static bool _hmac_sha384_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha384(), key, key_len, source, s_len, NULL, NULL);
	return !memcmp(target, result, t_len);
}

#define HMAC_SHA512_AUTH_DATA_LEN	36
static void _hmac_sha512_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha512(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, t_len);
}

static bool _hmac_sha512_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha512(), key, key_len, source, s_len, NULL, NULL);
	return !memcmp(target, result, t_len);
}

#define HMAC_RIPEMD160_AUTH_DATA_LEN	12
static void _hmac_ripemd160_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_ripemd160(), key, key_len, source, s_len, NULL, NULL);
	memcpy(target, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
}

static bool _hmac_ripemd160_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_ripemd160(), key, key_len, source, s_len, NULL, NULL);
	return !memcmp(target, result, t_len);
}


inline void xor_64(uint64_t* target, uint64_t* source) {
	target[0] ^= source[0];
	target[1] ^= source[1];
}

static uint8_t _K1[16] = {[0 ... 15] = 1};
static uint8_t _K2[16] = {[0 ... 15] = 2};
static uint8_t _K3[16] = {[0 ... 15] = 3};
static uint8_t _E[16] = {0, };
static unsigned char* aes_xcbc_mac_encrypt(AES_KEY* aes_key, unsigned char* message, uint16_t len) {
	uint8_t K1[16];
	uint8_t K2[16];
	uint8_t K3[16];
	memset(_E, 0, 16);

 	AES_KEY AES_K1;
	AES_encrypt((const unsigned char*)_K1, (unsigned char*)K1, aes_key);
 	AES_set_encrypt_key((const unsigned char*)K1, 128, &AES_K1);
	AES_encrypt((const unsigned char*)_K2, (unsigned char*)K2, aes_key);
	AES_encrypt((const unsigned char*)_K3, (unsigned char*)K3, aes_key);

	uint64_t* M = (uint64_t*)message;
	uint16_t n = len / 16 + !!(len % 16);
	for(int i = 0; i < n - 1; i++) {
		xor_64((uint64_t*)_E, M);
		AES_encrypt((const unsigned char*)_E, (unsigned char*)_E, &AES_K1);
		M += 2;
	}

	if(len % 16) { // less than 128 bits
		uint8_t _M[16] = {0, };
		memcpy(_M, M, len % 16);
		_M[len % 16] = 0x80;
		xor_64((uint64_t*)_E, (uint64_t*)_M);
		xor_64((uint64_t*)_E, (uint64_t*)K3);
		AES_encrypt((const unsigned char*)_E, (unsigned char*)_E, &AES_K1);
	} else { // 128bits
		xor_64((uint64_t*)_E, M);
		xor_64((uint64_t*)_E, (uint64_t*)K2);
		AES_encrypt((const unsigned char*)_E, (unsigned char*)_E, &AES_K1);
	}

	return _E;
}

#define AES_XCBC_MAC_AUTH_DATA_LEN	12
static void _aes_xcbc_mac_request(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	AES_set_encrypt_key((const unsigned char*)key, key_len * 8, &aes_key);

	unsigned char* result = aes_xcbc_mac_encrypt(&aes_key, source, s_len);
	memcpy(target, result, t_len);
}

static bool _aes_xcbc_mac_check(uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	AES_KEY aes_key;
	AES_set_encrypt_key((const unsigned char*)key, key_len * 8, &aes_key);

	unsigned char* result = aes_xcbc_mac_encrypt(&aes_key, source, s_len);
	return !memcmp(target, result, t_len);
}

int auth_get_icv_len(uint8_t algorithm) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			return 0;
		case SADB_AALG_MD5HMAC:
			return HMAC_MD5_AUTH_DATA_LEN;
		case SADB_AALG_SHA1HMAC:
			return HMAC_SHA1_AUTH_DATA_LEN;
		case SADB_X_AALG_SHA2_256HMAC:
			return HMAC_SHA256_AUTH_DATA_LEN;
		case SADB_X_AALG_SHA2_384HMAC:
			return HMAC_SHA384_AUTH_DATA_LEN;
		case SADB_X_AALG_SHA2_512HMAC:
			return HMAC_SHA512_AUTH_DATA_LEN;
		case SADB_X_AALG_RIPEMD160HMAC:
			return HMAC_RIPEMD160_AUTH_DATA_LEN;
		case SADB_X_AALG_AES_XCBC_MAC:
			return AES_XCBC_MAC_AUTH_DATA_LEN;
		case SADB_X_AALG_NULL:
			return 0;
	}

	return 0;
}

int auth_get_authdata_len(uint8_t algorithm) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			return 0;
		case SADB_AALG_MD5HMAC:
			return HMAC_MD5_AUTH_DATA_LEN;
		case SADB_AALG_SHA1HMAC:
			return HMAC_SHA1_AUTH_DATA_LEN;
		case SADB_X_AALG_SHA2_256HMAC:
			return HMAC_SHA256_AUTH_DATA_LEN;
		case SADB_X_AALG_SHA2_384HMAC:
			return HMAC_SHA384_AUTH_DATA_LEN - 4;
		case SADB_X_AALG_SHA2_512HMAC:
			return HMAC_SHA512_AUTH_DATA_LEN - 4;
		case SADB_X_AALG_RIPEMD160HMAC:
			return HMAC_RIPEMD160_AUTH_DATA_LEN;
		case SADB_X_AALG_AES_XCBC_MAC:
			return AES_XCBC_MAC_AUTH_DATA_LEN;
		case SADB_X_AALG_NULL:
			return 0;
	}

	return 0;
}

void auth_request(uint8_t algorithm, uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			break;
		case SADB_AALG_MD5HMAC:
			_hmac_md5_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_AALG_SHA1HMAC:
			_hmac_sha1_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_256HMAC:
			_hmac_sha256_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_384HMAC:
			_hmac_sha384_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_512HMAC:
			_hmac_sha512_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_RIPEMD160HMAC:
			_hmac_ripemd160_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_AES_XCBC_MAC:
			_aes_xcbc_mac_request(target, t_len, source, s_len, key, key_len);
			break;
		case SADB_X_AALG_NULL:
			break;
	}
}

bool auth_check(uint8_t algorithm, uint8_t* target, uint16_t t_len, uint8_t* source, uint16_t s_len, uint8_t* key, uint16_t key_len) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			return false;
		case SADB_AALG_MD5HMAC:
			return _hmac_md5_check(target, t_len, source, s_len, key, key_len);
		case SADB_AALG_SHA1HMAC:
			return _hmac_sha1_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_SHA2_256HMAC:
			return _hmac_sha256_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_SHA2_384HMAC:
			return _hmac_sha384_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_SHA2_512HMAC:
			return _hmac_sha512_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_RIPEMD160HMAC:
			return _hmac_ripemd160_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_AES_XCBC_MAC:
			return _aes_xcbc_mac_check(target, t_len, source, s_len, key, key_len);
		case SADB_X_AALG_NULL:
			return true;
		default:
			return false;
	}

	return false;
}
