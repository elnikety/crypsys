/*****************************************************************************/
/* skelxc.c - Main card-side skeleton server.                                */
/*                                                                           */
/*            This program is an example of how to handle multiple           */
/*            requests from the host with multiple threads serivicing        */
/*            each request as it arrives from the host.  Each request is     */
/*            assumed to be its own separate entity, and does not depend     */
/*            on any other request to be completed in order to be serviced   */
/*            Should requests need to be syncrhonized, linux provides a      */
/*            variety of manners in which to accomplish this.                */
/*            The general idea is to perform the following tasks:            */
/*            1. - Sign on via xcAttach to receive incoming requests from    */
/*                 the host.                                                 */
/*            2. - Spawn N worker threads, ( whose priorities can be         */
/*                 configured as desired ) each of which is capable of       */
/*                 servicing any request that would come from the host.      */
/*            3. - Wait for worker threads to complete                       */
/*                                                                           */
/*            Worker Thread Description                                      */
/*            The general idea is to spawn (via pthread_create(...)) N       */
/*            worker threads of chosen priorities.  Each thread will then    */
/*            perform an xcGetRequest to receive a request sent from the     */
/*            host.  Then, determine the nature of the request from the      */
/*            host, and call the appropriate function to handle the          */
/*            request.  Please note that for this example, synchronization   */
/*            and semaphores are not used, as they are not required for      */
/*            the limited examples we have here.  If synchronization or      */
/*            thread safety becomes an issue, simply use any of the          */
/*            various pthread functions to handle the situation as needed.   */
/*            After processing each request, send data back via a call to    */
/*            xcPutReply(..).                                                */
/*            Note: This setup allows for any combination of requests to     */
/*            be serviced. For example, the previous (scctk) version of      */
/*            the skeleton server was coded in such a manner that one had    */
/*            to specify at compile time, how many of each type of thread    */
/*            would be running on the card.  In this xCrypto example,        */
/*            any combination of requests can be serviced. In other words,   */
/*            If there are N threads, there could be N requests for keys     */
/*            being serviced, or N-1 requests for a sha-1 hash, and 1 req    */
/*            for a random number, etc, etc.                                 */
/*                                                                           */
/*****************************************************************************/

/* regular "C" includes */
#include <stdio.h>      /* printf et al              */
#include <stdlib.h>     /* malloc et al              */
#include <string.h>     /* string functions          */
#include <pthread.h>    /* thread functions          */
#include <errno.h>      /* for error numbers         */
#include <syslog.h>     /* for syslog functions      */
#include <unistd.h>     /* for sleep                 */

/* xCypto specific includes */
#include "xc_types.h"   /* xcrypto types             */
#include "xc_api.h"     /* xcrypto functions         */
#include "cmncryt2.h"   /* for hipri and lowpri      */

/* skeleton example specific includes */
#include "skelcmn.h"    /* skeleton utilities        */
#include "rngservi.h"   /* random number server      */
#include "modeli.h"     /* model server              */
#include "hshservi.h"   /* hash server               */
#include "adptservi.h"  /* adapter server            */
#include "desservi.h"   /* des server                */
#include "limservi.h"   /* large integer math server */
#include "pkaservi.h"   /* pka and dsa server        */
#include "aesserv.h"    /* aes server                */
#include "aesservi.h"   /* aes server                */

/* maximum size of header types */
#define MAX_HEADER_SIZE 64

/* maximum amt of data to pass back to host for this example */
/* maximum amt of data to grab from host */
#define GETBUFFER_SIZE 8192

/* high priority thread  mrb */
#define HIGH_PRIORITY 0
/* low priority thread mrb */
#define LOW_PRIORITY  2

/* file descriptor, used as handle to requests from host */
static int skeletonFD = 0;

/* worker thread, processes requests */
void 
skeleton_worker( int priority );

int 
main(int argc, char *argv[])
{
  /* debug spin loop vars */
  int          i, rc;
  /* array of handles to worker threads */
  pthread_t    workerThreads[MAX_THREADS];
  /* high priority value for threads */
  int highPriority = HIGH_PRIORITY;
  /* low priority value for threads */
  int lowPriority  =  LOW_PRIORITY;
  /* log message to be sent back to host */
  char log_message[64];

  /* ye old debug spin loop */
#ifdef DEBUG
  i = 0;
  int j = 1;
  for( ; ; )
  {
    /* Hint : Printing Out the Value of i inside the debug loop */
    /* and using minicom to capture the serial port output is a */
    /* great way to see if your program is running              */
    sprintf( log_message, "inside debug loop => i = %d\n", i );
    /* log message to host's /var/log/messages file */
    syslog( LOG_INFO+LOG_USER, log_message );

    sleep( 5 );

    i++;  /* good place for breakpoint */

    if( j == 28 )/* set j = 28 in the debugger to exit spin loop */
      break;
  }
#endif

  /* try to attach */
  if( (skeletonFD = xcAttachWithCDUoption( skeletonAgentID, NONCDUABLE ) ) <= 0 )
  {
    sprintf( log_message, "xcAttach returned 0x%d\n", skeletonFD );
    syslog( LOG_INFO+LOG_USER, log_message );
    return -1;
  }

  /* initialize memory mapping in the comm mgr.  see api doc for more info */
  if( !(xcInitMappings( skeletonFD ) == INITMAP_SUCCESS) )
  {
    syslog( LOG_INFO+LOG_USER, "xcInitMappings failed" );
    return -1;
  }

  /* initialize file descriptors needed by each thread to 
   * access card specific services 
   */
  rc = initFileDescriptors();

  if( rc != OK )
  {
    syslog(LOG_INFO+LOG_USER,"Init File Descriptors failed" );
    return -1;
  }

  syslog(LOG_INFO+LOG_USER, "Skeleton Server Starting..." );

  /* initialize threads */
  memset( workerThreads, 0x00, sizeof( workerThreads ) );

  /* spawn N-2 high priority worker threads */
  for( i = 0; i < MAX_THREADS -2; i++ )
  {
      pthread_create( &workerThreads[i],
                      NULL,
                      (void*) skeleton_worker ,
                      (void*) highPriority );
  }

  /* spawn 2 low priority worker threads */
  for( i = MAX_THREADS -2; i < MAX_THREADS; i++ )
  {
      pthread_create( &workerThreads[i],
                      NULL,
                      (void*)skeleton_worker ,
                      (void*) lowPriority );
  }

  /*********************************/
  /* let the worker threads work...*/
  /*********************************/

  /* wait for worker threads to complete */
  for( i = 0; i < MAX_THREADS; i++ )
  {
    pthread_join( workerThreads[i], NULL );
  }

  return 0;/* goodbye world */
}/* end main */

/* each skeleton worker thread will be a spin loop waiting for requests */
void 
skeleton_worker( int priority )
{
 
  int                 rc;          /* return code               */
  getReq_t            request;     /* request from host         */
  getReq_t            tempRequest; /* temp in case of interrupt */
  putRep_t            reply;       /* reply to host             */
  char              * getBuffer;
  char              * headerBuffer;
  char              * dataBuffer;
  unsigned long       requestID;   /* request id from host      */
  responseStruct    * pResponse;   /* response to host          */
  char                log_message[64]; /* log message to host   */
  xcVirtualPacket_t * pVPkt;       /* ptr to virtual packet from host */
  tagLenPtr_t         tlp[2];      /* tlp structs used for put reply  */
  tagLenPtr_t       * ptlp[2] = { &tlp[0], &tlp[1] };

  /* malloc space for request, and reply items */
  pResponse    = (responseStruct *) malloc( sizeof( responseStruct ) );
  getBuffer    = (char*) malloc( GETBUFFER_SIZE );
  headerBuffer = (char*) malloc( MAX_HEADER_SIZE );
  dataBuffer   = (char*) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );

  /* make sure mallocs completed */
  if( getBuffer    == NULL  || 
      dataBuffer   == NULL || 
      headerBuffer == NULL ||
      pResponse    == NULL )
  {
    if( getBuffer )
      free( getBuffer );
    if( dataBuffer )
      free( dataBuffer );
    if( headerBuffer )
      free( headerBuffer );
    if( pResponse )
      free( pResponse );

    return;
  }

  /* spin loop waiting for requests */
  for( ;; )
  {
    /* initialize variables for this request */
    memset( &request, 0x00, sizeof( getReq_t ) );
    memset( &tempRequest, 0x00, sizeof( getReq_t ) );
    memset( getBuffer, 0x00, GETBUFFER_SIZE );
    memset( headerBuffer, 0x00, MAX_HEADER_SIZE );
    memset( dataBuffer, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );
    memset( &reply, 0x00, sizeof( putRep_t ) );
    memset( pResponse, 0x00, sizeof( responseStruct ) );

    /* depending on the priority, pick starting and ending mrb's */
    if( priority == HIGH_PRIORITY )
    {
      request.startMRB = HIGH_PRIORITY;
      request.endMRB = LOW_PRIORITY;
    }
    else
    {
      request.startMRB = LOW_PRIORITY;
      request.endMRB = HIGH_PRIORITY;
    }

    /* our virtual packet should point to getBuffer */
    request.pVPacket = (void*)getBuffer;

    /* get the request */
    memcpy( &tempRequest, &request, sizeof( getReq_t ) );

    getit:
    rc = xcGetRequest( skeletonFD, &request );

    /* if interrupted, try again */
    if( rc == EINTR )
    {
      memcpy( &request, &tempRequest, sizeof( getReq_t ) );
      goto getit;
    }
    else if( rc == GETREQUEST_FAILED )
    {
      syslog(LOG_INFO+LOG_USER, "We just died from a getRequest" );
      goto cleanup;
    }

    /* find our virtual packet */
    pVPkt = (xcVirtualPacket_t *)request.pVPacket;
    
    /* If the virtual packet was null, the driver mapped the
     * virtual packet to the application's address space 
     */
    if( pVPkt == NULL )
      pVPkt = (xcVirtualPacket_t *)getBuffer;

    /* find our what request user is asking for */
    requestID = pVPkt->UserDefined;

    /* initialize response structure */
    pResponse->header       = headerBuffer;
    pResponse->headerLength = MAX_HEADER_SIZE;
    pResponse->data         = dataBuffer;
    pResponse->dataLength   = MAX_PADDED_PKA_TOKEN_LENGTH;

    /* handle request appropriately */
    switch( requestID )
    {
      case MODEL_REVERSE_REQUEST:
        threadModelServer( pVPkt, pResponse );
      break;

      case RNGSERV_RNG:
        randomNumberServer( pVPkt, pResponse );
      break;

      case ADAPTER_ID_REQUEST:
        adapterInfoServer( pVPkt, pResponse );
      break;

      case HSHSERV_HSH_SHA1:
        hashServer( pVPkt, pResponse );
      break;

      case LIMSERV_LIM:
        limServer( pVPkt, pResponse );
      break;

      case DESSERV_DES:
        DESServer( pVPkt, pResponse );
      break;

      case PKASERV_PKA:
        pkaServer( pVPkt, pResponse );
      break;

      case AESSERV_AES:
        AESServer( pVPkt, pResponse );
      break;

      default:
         //setupDummyReply( &request, &reply );
         sprintf( log_message, "unknown request type = 0x%lx\n", requestID );
         syslog(LOG_INFO+LOG_USER, log_message);
      break;
    }

    /* Save fields from request that are returned in the reply */
    reply.srcMRB          = request.srcMRB;
    reply.sizeHRB         = request.sizeHRB;
    reply.offsHRB         = request.offsHRB;
    reply.reqID           = pVPkt->RequestID;
    reply.pVPacket        = request.pVPacket;

    /* first item sent back is a header, 2nd is data block */
    tlp[0].tagLen.dataLen = pResponse->headerLength;
    tlp[0].tagLen.tag[0]  = TAG_OCPRB;

    /* if pVBuff1 is not null, use comm mgr's reply block, otherwise use ours */
    if( request.pVbuff1 != NULL )
    {
      memcpy( request.pVbuff1, pResponse->header, pResponse->headerLength );
      tlp[0].vptr = request.pVbuff1;
    }
    else
    {
      tlp[0].vptr           = pResponse->header;
    }
    
    tlp[1].tagLen.dataLen = pResponse->dataLength;
    tlp[1].tagLen.tag[0]  = TAG_REPDAT;

    /* if pVBuff2 is not null, use comm mgr's reply block, otherwise use ours */
    if( request.pVbuff2 != NULL )
    {
      memcpy( request.pVbuff2, pResponse->data, pResponse->dataLength );
      tlp[1].vptr = request.pVbuff2;
    }
    else
    {
      tlp[1].vptr           = pResponse->data;
    }

    reply.numTLP          = 2;/* 1 for header, 1 for data */
    reply.pTLV            = ptlp;

    reply.userDef         = pResponse->userDef;
    reply.status          = pResponse->status;

    /* send the reply back to the host */
    rc = xcPutReply( skeletonFD, &reply );

    if( rc != PUTREPLY_SUCCESS )
    {
      sprintf(log_message, "xcPutReply failed. rc = %i\n", rc);
      syslog(LOG_INFO+LOG_USER, log_message);
      goto cleanup;
    }

  }/* end for;; */

cleanup: /* something bad happened, free buffers, exit thread via return */

  if( getBuffer )
    free( getBuffer );

  if( headerBuffer )
    free( headerBuffer );

  if( dataBuffer )
    free( dataBuffer );

  if( pResponse )
    free( pResponse );

  return; /* return terminates thread */
}/* end skeleton_worker */


