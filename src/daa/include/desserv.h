/* structs, types, constants, and functions for des server */
#if !defined(_desserv_h_)
#define _desserv_h_

#include "xc_types.h"

/* indicates we want to perform a des server operation */
#define DESSERV_DES 0x6

/* always send 8 bytes for this example */
#define TEXT_BLOCK_LENGTH 8

/* Status codes */

/* everything a o.k. */
#define DES_OK         0
/* something unexpected happened */
#define DES_WHAT      -1
/* bad parameter passed */
#define DES_BADPARM   -2
/* system error, such as malloc failure */
#define DES_SYS_ERROR -3
/* des op failed */
#define DES_FAIL    -4

/* options */

/* encrypt 8 bytes of data */
#define DES_ENC8 0
/* decrypt 8 bytes of data */
#define DES_DEC8 1
/* triple encrypt 8 byts of data */
#define DES3_ENC8 2
/* triple decrypt 8 bytes of data */
#define DES3_DEC8 3
/* generate a mac */
#define DES_MACGEN 4

#pragma pack(1)
/* des server request header */
typedef struct desReqHdr_t
{
  unsigned long options;     /* options determines what op to perform */
  unsigned char data[8];     /* 8 bytes of data to work with          */
  unsigned char key[24];     /* holds up to a triple length key       */
  char          reserved[28];/* makes struct a multiple of 8 bytes    */
}desReqHdr_t;
#pragma pack()

#pragma pack(1)
/* des server reply header */
typedef struct desRepHdr_t
{
  unsigned long replyLength; /* length of reply in bytes */
  unsigned long pid;         /* process ID for servicing thread */
  /* padding to make struct at least 64 bytes long */
  char          reserved[ 64 - ( 2 * sizeof( unsigned long ) ) ];
}desRepHdr_t;
#pragma pack()

#endif
