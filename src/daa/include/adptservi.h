/* internal functions for adapterServer */
#if !defined(_adptservi_h_)
#define _adptservi_h_

#include "xc_types.h"

#include "adptserv.h"
#include "skelcmn.h"

/* adapter info server function, calls xcGetAdapterInfo */
void  
adapterInfoServer( xcVirtualPacket_t * pVPkt,
                   responseStruct    * pResponse );

#endif
