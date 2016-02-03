
/* C */
#include <assert.h>
#include <string.h>

/* sodium */
#include <sodium/crypto_auth_hmacsha256.h>
#include <sodium/crypto_secretbox_xsalsa20poly1305.h>
#include <sodium/utils.h>
#include <sodium/randombytes.h>


#include <erl_nif.h>

typedef ERL_NIF_TERM nif_term_t;
typedef ErlNifEnv nif_heap_t;
typedef ErlNifBinary nif_bin_t;
typedef ErlNifFunc nif_func_t;


#define BADARG enif_make_badarg(hp)



static const uint8_t macaroon_zerobytes[crypto_secretbox_xsalsa20poly1305_ZEROBYTES] = {0}; 

	
static nif_term_t
macaroon_secretbox(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* macaroon_secretbox(Plain_text, Nonce, Secret_key) -> Cipher_text. */
	nif_bin_t pt;
	nif_bin_t nc;
	nif_bin_t sk;
	nif_bin_t ct;
	nif_term_t raw;
	nif_term_t sub;
	if (argc != 3)
		return (BADARG);

	
	
	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_binary(hp, argv[0], &pt))
		return (BADARG);
	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);
	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);
	/* Check constraints on size and zero prefixing. */
	if (pt.size < crypto_secretbox_xsalsa20poly1305_ZEROBYTES)
		return (BADARG);
	
	if (memcmp((const void *)pt.data, &macaroon_zerobytes[0], crypto_secretbox_xsalsa20poly1305_ZEROBYTES) != 0)
		return (BADARG);
	if (nc.size != crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
		return (BADARG);
	if (sk.size != crypto_secretbox_xsalsa20poly1305_KEYBYTES)
		return (BADARG);
	
	/* Allocate space for cipher text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(pt.size, &ct))
		return (BADARG);
	
	/* Perform the crypto, strip leading zeros. */
	(void)crypto_secretbox_xsalsa20poly1305(ct.data, pt.data, pt.size, nc.data, sk.data);
	raw = enif_make_binary(hp, &ct);
	sub = enif_make_sub_binary(hp, 
			raw, 
			crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES, 
			ct.size - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
	return (sub);
};

static nif_term_t 
macaroon_secretbox_open(nif_heap_t *hp, int argc, const nif_term_t argv[])
{
	/* macaroon_secretbox_open(Cipher_text, Nonce, Secret_key) -> Plain_text. */
	nif_bin_t ct;
	nif_bin_t nc;
	nif_bin_t sk;
	nif_bin_t pt;
	nif_term_t raw;
	nif_term_t sub;
	if (argc != 3)
		return (BADARG);

	/* Unpack arguments ensuring they're suitably typed. */
	if (! enif_inspect_iolist_as_binary(hp, argv[0], &ct))
		return (BADARG);
	if (! enif_inspect_binary(hp, argv[1], &nc))
		return (BADARG);
	if (! enif_inspect_binary(hp, argv[2], &sk))
		return (BADARG);
	/* Check constraints on size and zero prefixing. */
	if (ct.size < crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)
		return (BADARG);
	
	if (memcmp((const void *)ct.data, &macaroon_zerobytes[0], crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES) != 0)
		return (BADARG);
	if (nc.size != crypto_secretbox_xsalsa20poly1305_NONCEBYTES)
		return (BADARG);
	if (sk.size != crypto_secretbox_xsalsa20poly1305_KEYBYTES)
		return (BADARG);
	
	/* Allocate space for plain text. NB: Passing ENOMEM as BADARG. */
	if (! enif_alloc_binary(ct.size, &pt))
		return (BADARG);
	
	/* Perform the crypto, strip leading zeros. */
	(void)crypto_secretbox_xsalsa20poly1305_open(pt.data, ct.data, ct.size, nc.data, sk.data);
	raw = enif_make_binary(hp, &pt);
	sub = enif_make_sub_binary(hp, 
			raw, 
			crypto_secretbox_xsalsa20poly1305_ZEROBYTES, 
			ct.size - crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
	return (sub);
};


static nif_func_t macaroon_exports[] = {
	{"secretbox", 3, macaroon_secretbox},
	{"secretbox_open",3,macaroon_secretbox_open}
};

ERL_NIF_INIT(macaroon, macaroon_exports, NULL, NULL, NULL, NULL)
