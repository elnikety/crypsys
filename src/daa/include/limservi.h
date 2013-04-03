/* lim server shared header file */
#if !defined(_limservi_h_)
#define _limservi_h_

#include "xc_types.h"

#include "limserv.h"
#include "skelcmn.h"

/* Main function for large integer math service thread */
void  
limServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse );

/* malloc failure in limServer */
#define LIMSERV_BAD_MALLOC -1
/* modmath call failed */
#define LIMSERV_MODMATH_FAILED -2
/* everything worked */
#define LIMSERV_OK 0

#endif
