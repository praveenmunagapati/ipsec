#include <net/ether.h>
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

#define HMAC_MD5_AUTH_DATA_LEN	12
static bool _hmac_md5(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_md5(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_MD5_AUTH_DATA_LEN);

					//TODO packet end check
					ip->length = endian16(endian16(ip->length) + HMAC_MD5_AUTH_DATA_LEN);
					packet->end += HMAC_MD5_AUTH_DATA_LEN;
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_MD5_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_md5(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_MD5_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->length = endian16(endian16(ip->length) - HMAC_MD5_AUTH_DATA_LEN);
						packet->end -= HMAC_MD5_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_MD5_AUTH_DATA_LEN];
			memcpy(auth_data, ah->auth_data, HMAC_MD5_AUTH_DATA_LEN);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_MD5_AUTH_DATA_LEN);

			unsigned char* result = _HMAC(EVP_md5(), auth_key, auth_key_length, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_MD5_AUTH_DATA_LEN);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_MD5_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}

	return false;
}

#define HMAC_SHA1_AUTH_DATA_LEN	12
static bool _hmac_sha1(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_sha1(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_SHA1_AUTH_DATA_LEN);
					ip->length = endian16(endian16(ip->length) + HMAC_SHA1_AUTH_DATA_LEN);
					packet->end += HMAC_SHA1_AUTH_DATA_LEN;
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA1_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_sha1(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_SHA1_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->length = endian16(endian16(ip->length) - HMAC_SHA1_AUTH_DATA_LEN);
						packet->end -= HMAC_SHA1_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_SHA1_AUTH_DATA_LEN];
			memcpy(auth_data, ah->auth_data, HMAC_SHA1_AUTH_DATA_LEN);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_SHA1_AUTH_DATA_LEN);

			unsigned char* result = _HMAC(EVP_sha1(), auth_key, auth_key_length,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_SHA1_AUTH_DATA_LEN);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_SHA1_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}

	return false;
}
/*
   Not implemented : No RFC
*/
static bool _keyed_md5(Packet* packet, SA* sa, uint8_t type) {
	return false;
}

static bool _keyed_sha1(Packet* packet, SA* sa, uint8_t type) {
	return false;
}

#define HMAC_SHA256_AUTH_DATA_LEN	12
static bool _hmac_sha256(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_sha256(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_SHA256_AUTH_DATA_LEN);
					ip->length = endian16(endian16(ip->length) + HMAC_SHA256_AUTH_DATA_LEN);
					packet->end += HMAC_SHA256_AUTH_DATA_LEN;
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA256_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_sha256(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_SHA256_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->length = endian16(endian16(ip->length) - HMAC_SHA256_AUTH_DATA_LEN);
						packet->end -= HMAC_SHA1_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_SHA256_AUTH_DATA_LEN];
			memcpy(auth_data, ah->auth_data, HMAC_SHA256_AUTH_DATA_LEN);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_SHA256_AUTH_DATA_LEN);

			unsigned char* result = _HMAC(EVP_sha256(), auth_key, auth_key_length,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_SHA256_AUTH_DATA_LEN);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_SHA256_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}

	return false;
}
/*
	TODO : Debug for 384, 512
*/
#define HMAC_SHA384_AUTH_DATA_LEN	28
static bool _hmac_sha384(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_sha384(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_SHA384_AUTH_DATA_LEN);
					ip->length = endian16(endian16(ip->length) + HMAC_SHA384_AUTH_DATA_LEN);
					packet->end += HMAC_SHA384_AUTH_DATA_LEN;
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA384_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_sha384(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_SHA384_AUTH_DATA_LEN)) {
						return false;
					}else {
						ip->length = endian16(endian16(ip->length) - HMAC_SHA384_AUTH_DATA_LEN);
						packet->end -= HMAC_SHA384_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_SHA384_AUTH_DATA_LEN - 4];
			memcpy(auth_data, ah->auth_data, HMAC_SHA384_AUTH_DATA_LEN - 4);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_SHA384_AUTH_DATA_LEN - 4);

			unsigned char* result = _HMAC(EVP_sha384(), auth_key, auth_key_length,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_SHA384_AUTH_DATA_LEN - 4);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_SHA384_AUTH_DATA_LEN - 4)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}

	return false;
}

#define HMAC_SHA512_AUTH_DATA_LEN	36
static bool _hmac_sha512(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_sha512(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_SHA512_AUTH_DATA_LEN);
					ip->length = endian16(endian16(ip->length) + HMAC_SHA512_AUTH_DATA_LEN);
					packet->end += HMAC_SHA512_AUTH_DATA_LEN;
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_SHA512_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_sha512(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_SHA512_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->length = endian16(endian16(ip->length) - HMAC_SHA512_AUTH_DATA_LEN);
						packet->end -= HMAC_SHA512_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_SHA512_AUTH_DATA_LEN - 4];
			memcpy(auth_data, ah->auth_data, HMAC_SHA512_AUTH_DATA_LEN - 4);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_SHA512_AUTH_DATA_LEN - 4);

			unsigned char* result = _HMAC(EVP_sha512(), auth_key, auth_key_length,  (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_SHA512_AUTH_DATA_LEN - 4);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_SHA512_AUTH_DATA_LEN - 4)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}
	return false;
}

#define HMAC_RIPEMD160_AUTH_DATA_LEN	12
static bool _hmac_ripemd160(Packet* packet, SA* sa, uint8_t type) {
	Ether* ether = (Ether*)(packet->buffer + packet->start);
        IP* ip = (IP*)ether->payload;

	switch(sa->ipsec_protocol) {
		case IP_PROTOCOL_ESP:
			{
			uint64_t* auth_key = ((SA_ESP*)sa)->auth_key;
			int auth_key_length = ((SA_ESP*)sa)->auth_key_length;

			switch(type) {
				case AUTH_REQUEST:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4);
					unsigned char* result = _HMAC(EVP_ripemd160(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					memcpy(ip->body + size, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
					return true;
					}
				case AUTH_CHECK:
					{
					uint16_t size = endian16(ip->length) - (ip->ihl * 4) - HMAC_RIPEMD160_AUTH_DATA_LEN;
					unsigned char* result = _HMAC(EVP_ripemd160(), auth_key, auth_key_length, ip->body, size, NULL, NULL);
					if(memcmp(ip->body + size, result, HMAC_RIPEMD160_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->length = endian16(endian16(ip->length) - HMAC_RIPEMD160_AUTH_DATA_LEN);
						packet->end -= HMAC_RIPEMD160_AUTH_DATA_LEN;
						return true;
					}
					}
			}
			}
			return false;
		case IP_PROTOCOL_AH:
			{
			AH* ah = (AH*)ip->body;
			uint64_t* auth_key = ((SA_AH*)sa)->auth_key;
			int auth_key_length = ((SA_AH*)sa)->auth_key_length;

			uint8_t ecn = ip->ecn;
			uint8_t dscp = ip->dscp;
			uint16_t flags_offset = ip->flags_offset;
			uint8_t ttl = ip->ttl;
			uint8_t auth_data[HMAC_RIPEMD160_AUTH_DATA_LEN];
			memcpy(auth_data, ah->auth_data, HMAC_RIPEMD160_AUTH_DATA_LEN);

			ip->ecn = 0; //tos
			ip->dscp = 0; //tos
			ip->ttl = 0;
			ip->flags_offset = 0;
			ip->checksum = 0;
			memset(ah->auth_data, 0, HMAC_RIPEMD160_AUTH_DATA_LEN);

			unsigned char* result = _HMAC(EVP_ripemd160(), auth_key, auth_key_length, (const unsigned char*)ip, endian16(ip->length), NULL, NULL);

			switch(type) {
				case AUTH_REQUEST:
					memcpy(ah->auth_data, result, HMAC_RIPEMD160_AUTH_DATA_LEN);
					return true;
				case AUTH_CHECK:
					if(memcmp(auth_data, result, HMAC_RIPEMD160_AUTH_DATA_LEN)) {
						return false;
					} else {
						ip->ecn = ecn;
						ip->dscp = dscp;
						ip->ttl = ttl;
						ip->flags_offset = flags_offset;
						return true;
					}
			}
			}
			return false;
	}

	return false;
}
/*
   Not implemented : No openssl function

	   AES-XCBC-MAC is not directly supported. However, it's very simple to
	   implement as it's based on AES-CBC for which there is support.
*/
static bool _aes_xcbc_mac(Packet* packet, SA* sa, uint8_t type) {
	return false;
}
/* 
   Not implemented : Only for BSD
*/
static bool _tcp_md5(Packet* packet, SA* sa, uint8_t type) {
	return false;
}

Authentication authentications[] = {
	{.authenticate = _hmac_md5, .auth_len = HMAC_MD5_AUTH_DATA_LEN},
	{.authenticate = _hmac_sha1, .auth_len = HMAC_SHA1_AUTH_DATA_LEN},
	{.authenticate = _keyed_md5, .auth_len = 0},
	{.authenticate = _keyed_sha1, .auth_len = 0},
	{.authenticate = _hmac_sha256, .auth_len = HMAC_SHA256_AUTH_DATA_LEN},
	{.authenticate = _hmac_sha384, .auth_len = HMAC_SHA384_AUTH_DATA_LEN},
	{.authenticate = _hmac_sha512, .auth_len = HMAC_SHA512_AUTH_DATA_LEN},
	{.authenticate = _hmac_ripemd160, .auth_len = HMAC_RIPEMD160_AUTH_DATA_LEN},
	{.authenticate = _aes_xcbc_mac, .auth_len = 0},
	{.authenticate = _tcp_md5, .auth_len = 0},
};

Authentication* get_authentication(int algorithm) {
	return &authentications[algorithm - 1];
}

