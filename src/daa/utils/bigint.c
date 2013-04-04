#include <bigint.h>

#include "../include/bi.h"


void *my_malloc(size_t size) {
	void *ret = malloc( size);
	return ret;
}

int init = 0;

void initialize()
{
	if(!init)
	{
		init = 1;
		bi_init( &my_malloc);
	}
}

int
BIpower(BigInt *a, BigInt *b, BigInt *n, BigInt *res)
{
	bi_t abi, bbi, nbi, resbi;
	char *hex;
	initialize();

	bi_new(abi);
	bi_new(bbi);
	bi_new(nbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(bbi, b->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	bi_mod_exp(resbi, abi, bbi, nbi);

	hex = bi_2_hex_char(resbi);
	memcpy(hex, res->nBuff, sizeof(hex));

	bi_free(abi);
	bi_free(bbi);
	bi_free(nbi);
	bi_free(resbi);

	return 0;
}

int
BImod(BigInt *a, BigInt *n, BigInt *res)
{
	bi_t abi, nbi, resbi;
	char *hex;
	initialize();

	bi_new(abi);
	bi_new(nbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	bi_mod(resbi, abi, nbi);

	hex = bi_2_hex_char(resbi);
	memcpy(hex, res->nBuff, sizeof(hex));

	bi_free(abi);
	bi_free(nbi);
	bi_free(resbi);

	return 0;
}

int
BImul(BigInt *a, BigInt *n, BigInt *res)
{
	bi_t abi, nbi, resbi;
	char *hex;
	initialize();

	bi_new(abi);
	bi_new(nbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	bi_mul(resbi, abi, nbi);

	hex = bi_2_hex_char(resbi);
	memcpy(hex, res->nBuff, sizeof(hex));

	bi_free(abi);
	bi_free(nbi);
	bi_free(resbi);

	return 0;
}

int
BIdiv(BigInt *a, BigInt *n, BigInt *res)
{
	bi_t abi, nbi, resbi;
	char *hex;
	initialize();

	bi_new(abi);
	bi_new(nbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	bi_div(resbi, abi, nbi);

	hex = bi_2_hex_char(resbi);
	memcpy(hex, res->nBuff, sizeof(hex));

	bi_free(abi);
	bi_free(nbi);
	bi_free(resbi);

	return 0;
}

int
BIsub(BigInt *a, BigInt *n, BigInt *res)
{
	bi_t abi, nbi, resbi;
	char *hex;
	initialize();

	bi_new(abi);
	bi_new(nbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	bi_sub(resbi, abi, nbi);

	hex = bi_2_hex_char(resbi);
	memcpy(hex, res->nBuff, sizeof(hex));

	bi_free(abi);
	bi_free(nbi);
	bi_free(resbi);

	return 0;
}

int
BIcmp(BigInt *a, BigInt *n)
{
	bi_t abi, nbi;
	int ret;
	initialize();

	bi_new(abi);
	bi_new(nbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(nbi, n->nBuff);

	ret = bi_cmp(abi, nbi);

	bi_free(abi);
	bi_free(nbi);

	return ret;
}

int
isPrime(BigInt *p)
{
	bi_t nbi;
	int is_prime;
	initialize();

	bi_new(nbi);
	bi_set_as_hex(nbi, p->nBuff);

	is_prime = bi_is_probable_prime(nbi);

	bi_free(nbi);

	return bits;
}

int
BIdivides(BigInt *a, BigInt *b)
{
	bi_t abi, bbi, resbi;
	int res;
	initialize();

	bi_new(abi);
	bi_new(bbi);
	bi_new(resbi);

	bi_set_as_hex(abi, a->nBuff);
	bi_set_as_hex(bbi, b->nBuff);

	bi_gcd(resbi, abi, bbi);

	if(bi_equals(resbi, bbi))
	{
		res = 1;
	}
	else
	{
		res = 0;
	}

	bi_free(abi);
	bi_free(bbi);
	bi_free(resbi);

	return res;
}

int
setBI(BigInt *n, int value)
{
	bi_t nbi;
	char *hex;
	initialize();

	bi_new(nbi);

	bi_set_as_si(nbi, value);

	hex = bi_2_hex_char(nbi);
	memcpy(hex, n->nBuff, sizeof(hex));

	bi_free(nbi);
	return 0;
}

unsigned int
noOfBits(BigInt *n)
{
	bi_t nbi;
	long bits;
	initialize();

	bi_new(nbi);
	bi_set_as_hex(nbi, n->nBuff);

	bits = bi_length(nbi);

	bi_free(nbi);

	return bits;
}

