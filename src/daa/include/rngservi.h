/* card-side random number service declarations */
#if !defined(_rngservi_h_)
#define _rngservi_h_

#include "xc_types.h"
#include "rngserv.h"
#include "skelcmn.h"

/* Main function for random number service thread */
void  
randomNumberServer( xcVirtualPacket_t * pVPkt,
                    responseStruct    * pResponse );

#endif
