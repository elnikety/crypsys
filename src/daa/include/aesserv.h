/* structs, types, constants, and functions for aesserv */
#if !defined(_aesserv_h_)
#define _aesserv_h_

#include "xc_types.h"

#define AESSERV_AES 0x8
#define AES_SYS_ERROR -1

/* AES Server request header */
typedef struct _aesReqHdr_t_
{
  xcAES_key_t     key;              
  xcAES_vector_t  init_v;
  unsigned char   source[16];
  unsigned char   prePadding[16];    
  unsigned char   postPadding[32];  
  unsigned long   options;
  unsigned char   dummy_buffer[12]; 
}aesReqHdr_t;

/* AES Server reply header */
typedef struct _aesRepHdr_t_
{
  int            reply_length; 
  int            pid; 
  unsigned char  dummy_buffer[56];
}aesRepHdr_t;

#endif
