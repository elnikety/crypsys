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

/**
 * returns res = a + b
 */
int
add(BigInt* a, BigInt* b, BigInt* res)
{
	//TODO
}

/**
 * returns res = a - b
 */
int
sub(BigInt* a, BigInt* b, BigInt* res)
{
	//TODO
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

	return 0;
}

int
BImul(BigInt *a, BigInt *b, BigInt *res)
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

	return bits;
}

