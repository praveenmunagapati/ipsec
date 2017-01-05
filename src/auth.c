#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

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
inline void _hmac_md5_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_md5(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_MD5_AUTH_DATA_LEN);
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_md5(), key, key_len, ip->body, size, NULL, NULL);
// 
// 			//TODO packet end check
// 			ip->length = endian16(endian16(ip->length) + HMAC_MD5_AUTH_DATA_LEN);
// 			packet->end += HMAC_MD5_AUTH_DATA_LEN;
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_MD5_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_MD5_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_MD5_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_md5(), key, key_len, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_MD5_AUTH_DATA_LEN);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
}

static bool _hmac_md5_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_md5(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_MD5_AUTH_DATA_LEN);

// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_MD5_AUTH_DATA_LEN;
// 			result = _HMAC(EVP_md5(), key, key_len, ip->body, size, NULL, NULL);
// 				return false;
// 			} else {
// 				ip->length = endian16(endian16(ip->length) - HMAC_MD5_AUTH_DATA_LEN);
// 				packet->end -= HMAC_MD5_AUTH_DATA_LEN;
// 				return true;
// 			}
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_MD5_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_MD5_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_MD5_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_md5(), key, key_len, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			if(memcmp(auth_data, result, HMAC_MD5_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->ecn = ecn;
// 				ip->dscp = dscp;
// 				ip->ttl = ttl;
// 				ip->flags_offset = flags_offset;
// 				return true;
// 			}
// 	}
// 
// 	return false;
}

#define HMAC_SHA1_AUTH_DATA_LEN	12
static void _hmac_sha1_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha1(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_SHA1_AUTH_DATA_LEN);

// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_sha1(), key, key_len, ip->body, size, NULL, NULL);
// 			memcpy(ip->body + size, result, HMAC_SHA1_AUTH_DATA_LEN);
// 			ip->length = endian16(endian16(ip->length) + HMAC_SHA1_AUTH_DATA_LEN);
// 			packet->end += HMAC_SHA1_AUTH_DATA_LEN;
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA1_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA1_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA1_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_sha1(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_SHA1_AUTH_DATA_LEN);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
	return;
}

inline bool _hmac_sha1_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha1(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_SHA1_AUTH_DATA_LEN);

// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result = _HMAC(EVP_sha1(), key, key_len, ip->body, size, NULL, NULL);
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA1_AUTH_DATA_LEN;
// 
// 			if(memcmp(ip->body + size, result, HMAC_SHA1_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->length = endian16(endian16(ip->length) - HMAC_SHA1_AUTH_DATA_LEN);
// 				packet->end -= HMAC_SHA1_AUTH_DATA_LEN;
// 				return true;
// 			}
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA1_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA1_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA1_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_sha1(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			if(memcmp(auth_data, result, HMAC_SHA1_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->ecn = ecn;
// 				ip->dscp = dscp;
// 				ip->ttl = ttl;
// 				ip->flags_offset = flags_offset;
// 				return true;
// 			}
// 	}
// 
// 	return false;
}

#define HMAC_SHA256_AUTH_DATA_LEN	12
static void _hmac_sha256_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha256(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_SHA256_AUTH_DATA_LEN);
// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_sha256(), key, key_len, ip->body, size, NULL, NULL);
// 			memcpy(ip->body + size, result, HMAC_SHA256_AUTH_DATA_LEN);
// 			ip->length = endian16(endian16(ip->length) + HMAC_SHA256_AUTH_DATA_LEN);
// 			packet->end += HMAC_SHA256_AUTH_DATA_LEN;
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA256_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA256_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA256_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_sha256(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_SHA256_AUTH_DATA_LEN);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
}
static bool _hmac_sha256_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha256(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_SHA256_AUTH_DATA_LEN);
// 
// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA256_AUTH_DATA_LEN;
// 			result = _HMAC(EVP_sha256(), key, key_len, ip->body, size, NULL, NULL);
// 			if(memcmp(ip->body + size, result, HMAC_SHA256_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->length = endian16(endian16(ip->length) - HMAC_SHA256_AUTH_DATA_LEN);
// 				packet->end -= HMAC_SHA1_AUTH_DATA_LEN;
// 				return true;
// 			}
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA256_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA256_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA256_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_sha256(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			if(memcmp(auth_data, result, HMAC_SHA256_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->ecn = ecn;
// 				ip->dscp = dscp;
// 				ip->ttl = ttl;
// 				ip->flags_offset = flags_offset;
// 				return true;
// 			}
// 	}
// 
// 	return false;
}
/*
	TODO : Debug for 384, 512
*/
#define HMAC_SHA384_AUTH_DATA_LEN	28
static void _hmac_sha384_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha384(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_SHA384_AUTH_DATA_LEN - 4);

// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_sha384(), key, key_len, ip->body, size, NULL, NULL);
// 			memcpy(ip->body + size, result, HMAC_SHA384_AUTH_DATA_LEN - 4);
// 			ip->length = endian16(endian16(ip->length) + HMAC_SHA384_AUTH_DATA_LEN - 4);
// 			packet->end += HMAC_SHA384_AUTH_DATA_LEN - 4;
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA384_AUTH_DATA_LEN - 4];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA384_AUTH_DATA_LEN - 4);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA384_AUTH_DATA_LEN - 4);
// 
// 			result = _HMAC(EVP_sha384(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_SHA384_AUTH_DATA_LEN - 4);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
// 
// 	return;
}

static bool _hmac_sha384_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha384(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_SHA384_AUTH_DATA_LEN - 4);

//	Ether* ether = (Ether*)(packet->buffer + packet->start);
//        IP* ip = (IP*)ether->payload;
//
//	unsigned char* result;
//	switch(protocol) {
//		case IP_PROTOCOL_ESP:;
//			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - (HMAC_SHA384_AUTH_DATA_LEN - 4);
//			result = _HMAC(EVP_sha384(), key, key_len, ip->body, size, NULL, NULL);
//			if(memcmp(ip->body + size, result, HMAC_SHA384_AUTH_DATA_LEN - 4)) {
//				return false;
//			}else {
//				ip->length = endian16(endian16(ip->length) - (HMAC_SHA384_AUTH_DATA_LEN - 4));
//				packet->end -= (HMAC_SHA384_AUTH_DATA_LEN - 4);
//				return true;
//			}
//		case IP_PROTOCOL_AH:;
//			AH* ah = (AH*)ip->body;
//			uint8_t ecn = ip->ecn;
//			uint8_t dscp = ip->dscp;
//			uint16_t flags_offset = ip->flags_offset;
//			uint8_t ttl = ip->ttl;
//			uint8_t auth_data[HMAC_SHA384_AUTH_DATA_LEN - 4];
//			memcpy(auth_data, ah->auth_data, HMAC_SHA384_AUTH_DATA_LEN - 4);
//
//			ip->ecn = 0; //tos
//			ip->dscp = 0; //tos
//			ip->ttl = 0;
//			ip->flags_offset = 0;
//			ip->checksum = 0;
//			memset(ah->auth_data, 0, HMAC_SHA384_AUTH_DATA_LEN - 4);
//
//			result = _HMAC(EVP_sha384(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
//
//			if(memcmp(auth_data, result, HMAC_SHA384_AUTH_DATA_LEN - 4)) {
//				return false;
//			} else {
//				ip->ecn = ecn;
//				ip->dscp = dscp;
//				ip->ttl = ttl;
//				ip->flags_offset = flags_offset;
//				return true;
//			}
//	}
//
//	return false;
}

#define HMAC_SHA512_AUTH_DATA_LEN	36
static void _hmac_sha512_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha512(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_sha512(), key, key_len, ip->body, size, NULL, NULL);
// 			memcpy(ip->body + size, result, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 			ip->length = endian16(endian16(ip->length) + (HMAC_SHA512_AUTH_DATA_LEN - 4));
// 			packet->end += (HMAC_SHA512_AUTH_DATA_LEN - 4);
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA512_AUTH_DATA_LEN - 4];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 
// 			result = _HMAC(EVP_sha512(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
}

static bool _hmac_sha512_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_sha512(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - (HMAC_SHA512_AUTH_DATA_LEN - 4);
// 			result = _HMAC(EVP_sha512(), key, key_len, ip->body, size, NULL, NULL);
// 			if(memcmp(ip->body + size, result, HMAC_SHA512_AUTH_DATA_LEN - 4)) {
// 				return false;
// 			} else {
// 				ip->length = endian16(endian16(ip->length) - (HMAC_SHA512_AUTH_DATA_LEN - 4));
// 				packet->end -= (HMAC_SHA512_AUTH_DATA_LEN - 4);
// 				return true;
// 			}
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_SHA512_AUTH_DATA_LEN - 4];
// 			memcpy(auth_data, ah->auth_data, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_SHA512_AUTH_DATA_LEN - 4);
// 
// 			result = _HMAC(EVP_sha512(), key, key_len,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			if(memcmp(auth_data, result, HMAC_SHA512_AUTH_DATA_LEN - 4)) {
// 				return false;
// 			} else {
// 				ip->ecn = ecn;
// 				ip->dscp = dscp;
// 				ip->ttl = ttl;
// 				ip->flags_offset = flags_offset;
// 				return true;
// 			}
// 	}
// 	return false;
}

#define HMAC_RIPEMD160_AUTH_DATA_LEN	12
static void _hmac_ripemd160_request(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_ripemd160(), key, key_len, source, len, NULL, NULL);
	memcpy(target, result, HMAC_RIPEMD160_AUTH_DATA_LEN);

// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4);
// 			result = _HMAC(EVP_ripemd160(), key, key_len, ip->body, size, NULL, NULL);
// 			memcpy(ip->body + size, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 			ip->length = endian16(endian16(ip->length) + HMAC_RIPEMD160_AUTH_DATA_LEN);
// 			packet->end += HMAC_RIPEMD160_AUTH_DATA_LEN;
// 			return;
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_RIPEMD160_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_ripemd160(), key, key_len, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			memcpy(ah->auth_data, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 			ip->ecn = ecn;
// 			ip->dscp = dscp;
// 			ip->flags_offset = flags_offset;
// 			ip->ttl = ttl;
// 			return;
// 	}
// 
// 	return;
}

static bool _hmac_ripemd160_check(uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	unsigned char* result = _HMAC(EVP_ripemd160(), key, key_len, source, len, NULL, NULL);
	return !!memcmp(target, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 	Ether* ether = (Ether*)(packet->buffer + packet->start);
//         IP* ip = (IP*)ether->payload;
// 
// 	unsigned char* result;
// 	switch(protocol) {
// 		case IP_PROTOCOL_ESP:;
// 			uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_RIPEMD160_AUTH_DATA_LEN;
// 			result = _HMAC(EVP_ripemd160(), key, key_len, ip->body, size, NULL, NULL);
// 			if(memcmp(ip->body + size, result, HMAC_RIPEMD160_AUTH_DATA_LEN)) {
// 				return false;
// 			} else {
// 				ip->length = endian16(endian16(ip->length) - HMAC_RIPEMD160_AUTH_DATA_LEN);
// 				packet->end -= HMAC_RIPEMD160_AUTH_DATA_LEN;
// 				return true;
// 			}
// 		case IP_PROTOCOL_AH:;
// 			AH* ah = (AH*)ip->body;
// 			uint8_t ecn = ip->ecn;
// 			uint8_t dscp = ip->dscp;
// 			uint16_t flags_offset = ip->flags_offset;
// 			uint8_t ttl = ip->ttl;
// 			uint8_t auth_data[HMAC_RIPEMD160_AUTH_DATA_LEN];
// 			memcpy(auth_data, ah->auth_data, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 
// 			ip->ecn = 0; //tos
// 			ip->dscp = 0; //tos
// 			ip->ttl = 0;
// 			ip->flags_offset = 0;
// 			ip->checksum = 0;
// 			memset(ah->auth_data, 0, HMAC_RIPEMD160_AUTH_DATA_LEN);
// 
// 			result = _HMAC(EVP_ripemd160(), key, key_len, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);
// 
// 			if(memcmp(auth_data, result, HMAC_RIPEMD160_AUTH_DATA_LEN)) {
// 				return false;
// 		       	} else {
// 			       	ip->ecn = ecn;
// 				ip->dscp = dscp;
// 				ip->ttl = ttl;
// 				ip->flags_offset = flags_offset;
// 				return true;
// 			}
// 	}
// 
// 	return false;
}

void auth_request(uint8_t algorithm, uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint16_t key_len) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			break;
		case SADB_AALG_MD5HMAC:
			_hmac_md5_request(target, source, len, key, key_len);
			break;
		case SADB_AALG_SHA1HMAC:
			_hmac_sha1_request(target, source, len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_256HMAC:
			_hmac_sha256_request(target, source, len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_384HMAC:
			_hmac_sha384_request(target, source, len, key, key_len);
			break;
		case SADB_X_AALG_SHA2_512HMAC:
			_hmac_sha512_request(target, source, len, key, key_len);
			break;
		case SADB_X_AALG_RIPEMD160HMAC:
			_hmac_ripemd160_request(target, source, len, key, key_len);
			break;
		case SADB_X_AALG_AES_XCBC_MAC:
			break;
		case SADB_X_AALG_NULL:
			break;
	}
}

bool auth_check(uint8_t algorithm, uint8_t* target, uint8_t* source, uint16_t len, uint8_t* key, uint8_t key_len) {
	switch(algorithm) {
		case SADB_AALG_NONE:
			return false;
		case SADB_AALG_MD5HMAC:
			return _hmac_md5_check(target, source, len, key, key_len);
		case SADB_AALG_SHA1HMAC:
			return _hmac_sha1_check(target, source, len, key, key_len);
		case SADB_X_AALG_SHA2_256HMAC:
			return _hmac_sha256_check(target, source, len, key, key_len);
		case SADB_X_AALG_SHA2_384HMAC:
			return _hmac_sha384_check(target, source, len, key, key_len);
		case SADB_X_AALG_SHA2_512HMAC:
			return _hmac_sha512_check(target, source, len, key, key_len);
		case SADB_X_AALG_RIPEMD160HMAC:
			return _hmac_ripemd160_check(target, source, len, key, key_len);
		case SADB_X_AALG_AES_XCBC_MAC:
			return false;
		case SADB_X_AALG_NULL:
			return false;
		default:
			return false;

	}

	return false;
}
// Authentication authentications[] = {
// 	{.authenticate = _hmac_md5, .auth_len = HMAC_MD5_AUTH_DATA_LEN},
// 	{.authenticate = _hmac_sha1, .auth_len = HMAC_SHA1_AUTH_DATA_LEN},
// 	{.authenticate = _keyed_md5, .auth_len = 0},
// 	{.authenticate = _keyed_sha1, .auth_len = 0},
// 	{.authenticate = _hmac_sha256, .auth_len = HMAC_SHA256_AUTH_DATA_LEN},
// 	{.authenticate = _hmac_sha384, .auth_len = HMAC_SHA384_AUTH_DATA_LEN},
// 	{.authenticate = _hmac_sha512, .auth_len = HMAC_SHA512_AUTH_DATA_LEN},
// 	{.authenticate = _hmac_ripemd160, .auth_len = HMAC_RIPEMD160_AUTH_DATA_LEN},
// 	{.authenticate = _aes_xcbc_mac, .auth_len = 0},
// 	{.authenticate = _tcp_md5, .auth_len = 0},
// };
