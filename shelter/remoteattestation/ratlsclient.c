/* client-tls.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* the usual suspects */
#ifdef SGX_RATLS_MUTUAL
#include <assert.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#define DEFAULT_PORT 11111
#define QUOTE_BUFF_SIZE 8192

#include <sgx_quote.h>

#include "ra.h"
#ifdef SGX_RATLS_MUTUAL
#include "ra-attester.h"
#endif
#include "ra-challenger.h"

static int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX * store)
{
	(void)preverify;
	int ret = verify_sgx_cert_extensions(store->certs->buffer,
					     store->certs->length);

	fprintf(stderr, "Verifying SGX certificate extensions ... %s\n",
		ret == 0 ? "Success" : "Failure");
	return !ret;
}

#ifdef SGX_RATLS_MUTUAL
extern struct ra_tls_options my_ra_tls_options;
#endif

int ra_tls_echo(int sockfd, unsigned char* mrenclave, unsigned char* mrsigner)
{
	wolfSSL_Debugging_ON();

	wolfSSL_Init();

	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
		goto err;
	}

#ifdef SGX_RATLS_MUTUAL
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);

	create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						    SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);
#endif

	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}
	fprintf(stdout, "wolfSSL_CTX_set_verify success.\n");

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

	if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		goto err_ssl;
	}

	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);

	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	sgx_report_body_t *body = NULL;
	uint8_t quote_buff[QUOTE_BUFF_SIZE] = {0,};
	get_quote_from_cert(der, derSz, (sgx_quote_t*)quote_buff);
	sgx_quote_t* quote = (sgx_quote_t*)quote_buff;
	body = &quote->report_body;
	printf("Server's SGX identity:\n");
	printf("  . MRENCLAVE = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_enclave.m[i]);
		mrenclave[i] = body->mr_enclave.m[i];
	}
	printf("\n");
	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_signer.m[i]);
		mrsigner[i] = body->mr_signer.m[i];
	}
	printf("\n");

	const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	size_t len = strlen(http_request);
	if (wolfSSL_write(ssl, http_request, len) != (int)len) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}
	char buff[256];
	memset(buff, 0, sizeof(buff));
	if (wolfSSL_read(ssl, buff, sizeof(buff) - 1) == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}
	printf("Server:\n%s\n", buff);
err_ssl:
	wolfSSL_free(ssl);
err_ctx:
	wolfSSL_CTX_free(ctx);
err:
	wolfSSL_Cleanup();

	return 0;
}

int ra_tls_enc_protocol(int sockfd, unsigned char* sendmsg, unsigned int sendmsglen,  unsigned char* retmsg, unsigned int* recemsglen)
{
	wolfSSL_Debugging_ON();

	wolfSSL_Init();

	WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
	if (!ctx) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
		goto err;
	}

#ifdef SGX_RATLS_MUTUAL
	uint8_t key[2048];
	uint8_t crt[8192];
	int key_len = sizeof(key);
	int crt_len = sizeof(crt);

	create_key_and_x509(key, &key_len, crt, &crt_len, &my_ra_tls_options);
	int ret = wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, key_len,
						    SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);

	ret = wolfSSL_CTX_use_certificate_buffer(ctx, crt, crt_len,
						 SSL_FILETYPE_ASN1);
	assert(SSL_SUCCESS == ret);
#endif

	wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);

	WOLFSSL *ssl = wolfSSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
		goto err_ctx;
	}
	fprintf(stdout, "wolfSSL_CTX_set_verify success.\n");

	/* Attach wolfSSL to the socket */
	wolfSSL_set_fd(ssl, sockfd);

	if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
		goto err_ssl;
	}

	WOLFSSL_X509 *srvcrt = wolfSSL_get_peer_certificate(ssl);

	int derSz;
	const unsigned char *der = wolfSSL_X509_get_der(srvcrt, &derSz);
	sgx_report_body_t *body = NULL;
	uint8_t quote_buff[QUOTE_BUFF_SIZE] = {0,};
	uint8_t mrenclave[32] = {0,};
	uint8_t mrsigner[32] = {0,};
	get_quote_from_cert(der, derSz, (sgx_quote_t*)quote_buff);
	sgx_quote_t* quote = (sgx_quote_t*)quote_buff;
	body = &quote->report_body;
	printf("Server's SGX identity:\n");
	printf(" Inclavared enclave. MRENCLAVE = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_enclave.m[i]);
		mrenclave[i] = body->mr_enclave.m[i];
	}
	printf("\n");
	printf("  . MRSIGNER  = ");
	for (int i = 0; i < SGX_HASH_SIZE; ++i){
		printf("%02x", body->mr_signer.m[i]);
		mrsigner[i] = body->mr_signer.m[i];
	}
	printf("\n");

	//const char *http_request = "GET / HTTP/1.0\r\n\r\n";
	//size_t len = strlen(http_request);
	printf("Send msg and msg length is: %s\n %d\n", sendmsg, sendmsglen);
	if (wolfSSL_write(ssl, sendmsg, sendmsglen) != (unsigned int)sendmsglen) {
		fprintf(stderr, "ERROR: failed to write\n");
		goto err_ssl;
	}
	char buff[1024];
	memset(buff, 0, sizeof(buff));
	int retcount = 0;
	retcount = wolfSSL_read(ssl, buff, sizeof(buff) - 1);
	if (retcount == -1) {
		fprintf(stderr, "ERROR: failed to read\n");
		goto err_ssl;
	}
	*recemsglen = (unsigned int)retcount;
        for (int i = 0; i < retcount; i++){
                printf("%02x", buff[i]);
                retmsg[i] = buff[i];
	}
	printf("Receive msg:\n%s\n", buff);
err_ssl:
	wolfSSL_free(ssl);
err_ctx:
	wolfSSL_CTX_free(ctx);
err:
	wolfSSL_Cleanup();

	return 0;
}
