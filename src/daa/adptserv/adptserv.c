/*********************************************************************** 
 * adptserv.c - Skeleton Adapter Information server.                   * 
 *              This function services yCrypto requests for adapter    * 
 *              information                                            * 
 *                                                                     * 
 ***********************************************************************/

#include <stdlib.h>     /* malloc, etc          */
#include <string.h>     /* memset, etc          */
#include <pthread.h>    /* for phtread_self     */

#include "xc_api.h"     /* xcrypto api calls    */
#include "xc_types.h"   /* xcrypto types        */

#include "adptservi.h"  /* header for this file */
#include "skelcmn.h"    /* common functions     */

void  
adapterInfoServer( xcVirtualPacket_t * pVPkt,
                   responseStruct    * pResponse )
{
  /* return code for various functions */
  long                  rc;
  /* reply header */
  adptHdr_t             replyHeader;
  /* pointer to adapter info struct which holds adpater information */
  xcAdapterInfo_t     * pInfo = NULL;
  /* process id for this function call */
  pthread_t             pid = pthread_self();
  /*length of adapter info, used as parameter to xcGetConfig */
  unsigned long         infoLen = sizeof(xcAdapterInfo_t);

  /* clear out any relevant vars, and do initializations */
  memset( &replyHeader, 0x00, sizeof( adptHdr_t ) );
  replyHeader.pid = (int)pid;

  /* malloc space for pInfo */
  pInfo = (xcAdapterInfo_t *) malloc( sizeof( xcAdapterInfo_t ) );

  /* if we can't malloc, need to set up dummy reply and return */
  if( pInfo == NULL )
  {
    createDummyResponse( pResponse, ADPTSERV_MALLOC_ERR, pid );
    return;
  }

  /* make sure the request is what we expect, and perform call to config */
  switch( pVPkt->UserDefined )
  {

   case ADAPTER_ID_REQUEST:

     /* gather adapter information */
     if( ( rc = xcGetConfig( getFileDescriptor( FD_XCRYPTO ),
                             pInfo,
                             &infoLen ) ) != ADPTSERV_OK )
       pResponse->status = GETCONFIG_FAILED;
     else
       pResponse->status = ADPTSERV_OK;

   break;

   default:

     /* we should never get here, but check just in case */
     pResponse->status = ADPTSERV_BAD_PARM;

   break;
  }/* end switch */

  /* set up response */
  if( pResponse->status == ADPTSERV_OK )
  {
    pResponse->headerLength = sizeof( adptHdr_t );
    memcpy( pResponse->header, &replyHeader, sizeof( adptHdr_t ) );
    infoLen = ( (infoLen + 7 ) / 8 ) * 8; /* convert to next mult of 8 */
    pResponse->dataLength = infoLen;
    memcpy( pResponse->data, pInfo, infoLen );
    pResponse->userDef = 0;
  }
  else
  {
    /* request failed, return a dummy response with proper status */
    createDummyResponse( pResponse, pResponse->status, pid );
  }

  /* free buffer to avoid memory leakage */
  if( pInfo )
    free( pInfo );

  return;
}/* end function */


