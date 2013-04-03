/* internal helper functions for aes server */
#if !defined(_aesservi_h_)
#define _aesservi_h_

#include "xc_types.h"

#include "aesserv.h"
#include "skelcmn.h"

/*
 * Main function for AES service thread
 */
void  
AESServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse );

#endif
