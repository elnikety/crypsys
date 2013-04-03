/* internal helper functions for des server */
#if !defined(_desservi_h_)
#define _desservi_h_

#include "xc_types.h"

#include "desserv.h"
#include "adptservi.h"
#include "skelcmn.h"

/*
* Main function for DES service thread
*/
void  
DESServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse );

/* Encrypt or Decrypt 8 bytes using a single length ( 8 bytes ) DES Key */
void  
encOrDec8Bytes( responseStruct * pResponse,
                int              userRequest,
                unsigned char  * pKey,
                unsigned char  * pData );

/* Encrypt or Decrypt 8 Bytes using a triple length ( 24 bytes ) DES Key */
void 
des3EncOrDec( responseStruct * pResponse,
              int              userRequest,
              unsigned char  * pKey,
              unsigned char  * pData );

/* Generate a MAC */
void 
desMACGen( responseStruct * pResponse,
           unsigned char  * pKey,
           unsigned char  * pData );

#endif
