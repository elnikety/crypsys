/* structs, types, constants, and functions for hash server */
#if !defined(_hshserv_h_)
#define _hshserv_h_

#include "xc_types.h"

/*
* Status codes
*/
/* Hash Calculated without error */
#define HSH_OK         0
/* something unusual happened */
#define HSH_WHAT      -1
/* bad parameter passed */
#define HSH_BADPARM   -2
/* system error, such as malloc failure */
#define HSH_SYS_ERROR -3

/* SHA Hash needs to return 24 bytes, in order to be a multiple of 8 bytes */
#define SHA1_PADDED_LEN 24

#pragma pack(1)
/* hash header */
typedef struct {
  int dataLen;   /* length of data in bytes */
  int pid;       /* process id of servicing thread */
  /* pad to make struct at least 64 bytes */
  char dummy[ 64 - ( 2 * ( sizeof( int ) ) ) ];
}hashHdr_t;
#pragma pack()

/* id for hash server */
#define HSHSERV_HSH_SHA1  0x4


#endif
