/* header for hash server */
#if !defined(_hshservi_h_)
#define _hshservi_h_

#include "xc_types.h" /* for xcVirtualPacket_t */
#include "hshserv.h"
#include "skelcmn.h"

/* Main function for hash service thread */
void  
hashServer( xcVirtualPacket_t * pVPkt, 
            responseStruct    * pResponse );

#endif
