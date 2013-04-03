/* structs, types, constants, and functions for lim server */
#if !defined(_limserv_h_)
#define _limserv_h_

#include "limserv.h"

/* maximum size for each int is 256 bytes ( 2048 bits ) */
#define MAX_LIM_BUF_SIZE 256

/* id for large integer math server */
#define LIMSERV_LIM 0x5

#pragma pack(1)
/* request header, contains all request info */
typedef struct {
  int cmd;                      /* large int math operation to perform */
  int aBits;                    /* number of bits in a                 */
  int aBytes;                   /* number of bytes in a                */
  char aBuff[MAX_LIM_BUF_SIZE]; /* a buffer                            */
  int bBits;                    /* number of bits in b                 */
  int bBytes;                   /* number of bytes in b                */
  int bBuff[MAX_LIM_BUF_SIZE];  /* b buffer                            */
  int nBits;                    /* number of bits in n                 */
  int nBytes;                   /* number of bytes in n                */
  int nBuff[MAX_LIM_BUF_SIZE];  /* n buffer                            */
  int pad;                      /* pad to make a multiple of 8 bytes   */
}limReqHdr_t;
#pragma pack()

#pragma pack(1)
/* reply header, C is always the reply, and is sent back as pvpkt[2] */
typedef struct {
  int  pid;       /* process id of servicing thread */
  int  cBytes;    /* number of bytes in reply C     */
  int  cBits;     /* number of bits in C            */
  /* reserved to make struct at least 64 bytes      */
  char reserved[ 64 - ( 3 * sizeof( int ) ) ];
}limReply_t;
#pragma pack()

#endif
