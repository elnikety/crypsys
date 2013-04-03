/* Main function for thread model service */
#if !defined(_modeli_h_)
#define _modeli_h_

#include "xc_types.h" /* for xcVirtualPacket_t */
#include "model.h"    /* include host and shared items */
#include "skelcmn.h"

void  
threadModelServer( xcVirtualPacket_t * pVPkt,
                   responseStruct    * pResponse );

#endif
