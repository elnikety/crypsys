/**
 * Hash utilities
 */

// refer to Crypto.h in DAA all phases
#ifndef BIGINT_H_
#define BIGINT_H_

#include "bigint.h"

void
hashName(char *bsn, BigInt *n);

void
keyHash(BigInt *rho, char *daaSeed, char *pkPrimeHash, unsigned *cnt, char *hash);

void
hashString(char *cont, int len, char *hash);

#endif
