/***********************************************************************
 * adptHost.c - Host Skeleton sample program.                          *
 *              This program is an example of how to get adapter       *
 *              status and return it to the host as part of a menu     *
 *              of options (skelhost.c is the main server)             *
 *                                                                     *
 ***********************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef NT_ON_I386
  #include <windows.h> /* require dfor handle */
#endif

#include "xc_types.h"
#include "xc_host.h"

#include "skelServers.h"
#include "skelcmn.h"
#include "adptserv.h"
#include "../../rte/shared/util.h"

void
do_adptserv( xcAdapterHandle_t * pAdapterHandle )
{
  int                rc     = 0;
  int                i      = 0;
  xcRB_t             requestBlock;  /* request block to be sent to card */
  adptHdr_t          requestHdr, replyHdr;/* request and reply headers */
  xcAdapterInfo_t    adapterInfo;
  int                otelloLen = sizeof( adapterInfo.HdwOtelloECID );
  int                rigolettoLen = sizeof( adapterInfo.HdwRigolettoID );
  int                adapterIDLen = sizeof( adapterInfo.AdapterID );
  unsigned char      buffer[64];    /* for printing */

  printf("-----------------------------------------------------------------\n");
  printf("Gathering Information about your xCrypto Card...Please wait......\n");
  printf("-----------------------------------------------------------------\n");

  memset( &requestBlock, 0x00, sizeof( xcRB_t ) );

  memset( &requestHdr, 0x00, sizeof( adptHdr_t ) );
  memset( &replyHdr, 0x00, sizeof( adptHdr_t ) );
  memset( &adapterInfo, 0x00, sizeof( xcAdapterInfo_t ) );

  /* request block info */
  requestBlock.AgentID                   = HTOAS( skeletonAgentID );

  requestBlock.UserDefined               = HTOAL( ADAPTER_ID_REQUEST );
  requestBlock.ReplyDataLength           = sizeof( xcAdapterInfo_t );
  requestBlock.ReplyDataAddr             = (unsigned char*)&adapterInfo;

  /* request control block should hold adptHDR which contains a length and ptr */
  requestBlock.RequestControlBlkLength   = sizeof( adptHdr_t );
  requestBlock.RequestControlBlkAddr     = (unsigned char*)&requestHdr;

  /* request data info */
  requestBlock.RequestDataLength         = 0;
  requestBlock.RequestDataAddress        = NULL;

  /* reply control block */
  requestBlock.ReplyControlBlkLength     = sizeof( adptHdr_t );
  requestBlock.ReplyControlBlkAddr       = (unsigned char*)&replyHdr;

  /* issue the request, wait for it to complete */
  if( ( rc = xcRequest( *pAdapterHandle, &requestBlock ) ) != 0 )
  {
    printf( "xcRequest failed rc = 0x%x\n", rc );
    xcCloseAdapter( *pAdapterHandle );
    exit( 1 );
  }

  switch( ATOHL( requestBlock.Status ) )
  {
    case ADPTSERV_OK:
      printf( "4765 Adapter Information -->\n" );
      printf( "Rigoletto Version (Code Version)\n" );

      for( i = 0; i < rigolettoLen; i++ )
      {
        printf( " %02x", adapterInfo.HdwRigolettoID[i] );
      }
      printf( "\n" );

      printf( "Otello ECID ( version in silicon )\n" );

      for( i = 0; i < otelloLen; i++ )
      {
        printf( " %02x", adapterInfo.HdwOtelloECID[i] );
      }
      printf( "\n" );

      printf( "POST 0 Version --> %02x%02x\n", 
              (unsigned int)adapterInfo.POST_Version.POST0Version.ver,
              (unsigned int)adapterInfo.POST_Version.POST0Version.rel );
      printf( "POST 1 Version --> %02x%02x\n", 
              (unsigned int)adapterInfo.POST_Version.POST1Version.ver,
              (unsigned int)adapterInfo.POST_Version.POST1Version.rel );
      printf( "MiniBoot 0 Version --> %02x%02x\n", 
              (unsigned int)adapterInfo.MiniBoot_Version.MiniBoot0Version.ver,
              (unsigned int)adapterInfo.MiniBoot_Version.MiniBoot0Version.rel );
      printf( "MiniBoot 1 Version --> %02x%02x\n", 
              (unsigned int)adapterInfo.MiniBoot_Version.MiniBoot1Version.ver,
              (unsigned int)adapterInfo.MiniBoot_Version.MiniBoot1Version.rel );

      /* No string terminator in OS_Name */
      memset( buffer, 0x00, sizeof( buffer ) );
      memcpy( buffer, adapterInfo.OS_Name, sizeof( adapterInfo.OS_Name ) );
      printf( "OS Name     --> %s\n", buffer );
      printf( "OS Version  --> %02x\n",
               adapterInfo.OS_Version.osVersion );
      printf( "OS Release  --> %02x\n",
               adapterInfo.OS_Version.osRelease );
      printf( "OS Mod      --> %02x\n",
               adapterInfo.OS_Version.osMod );
      printf( "osFix       --> %02x\n",
               adapterInfo.OS_Version.osFix );
      printf( "Adapter CPU Speed --> %d\n",
               ATOHS( adapterInfo.CPU_Speed ) );
      printf( "Hardware DES Level --> %02x\n",
               adapterInfo.HardwareOptions.DES_level );
      printf( "Hardware RSA Level --> %02x\n",
               adapterInfo.HardwareOptions.RSA_level );

      printf( "Adapter ID -->\n" );
      for( i = 0; i < adapterIDLen; i++ )
      {
        printf( " %02x", adapterInfo.AdapterID[i] );
      }
      printf( "\n" );

      printf( "Flash Size (MB) --> %ld\n", adapterInfo.flashSize );
      printf( "bbram Size (KB) --> %ld\n", adapterInfo.bbramSize );
      printf( "dram  Size (KB) --> %ld\n",
               ATOHL( adapterInfo.dramSize ) );

      printf( "pid of thread which processed this request = %ld\n",
               ATOHL( replyHdr.pid ) );
    break;

    case GETCONFIG_FAILED:
      printf( "GETCONFIG FAILED on xCrypto Card\n" );
    break;

    case ADPTSERV_BAD_PARM:
    default:
      printf("Unrecognized status returned from card\n" );
    break;
  }

}
