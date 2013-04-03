/*********************************************************************** 
 * sharedUtils.c - Skeleton shared card and host side utilities.       * 
 *                 These functions assist with the skeleton utilities. * 
 *                                                                     * 
 ***********************************************************************/
//card side utilities that may also be used on the host
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NT_ON_I386
  #include <sys/ioctl.h>
  #include <sys/types.h>
  #include <fcntl.h>
  #include <errno.h>
#endif

#include <skelcmn.h>

#define ERROR -1

#ifndef NT_ON_I386

static int  fileDescriptor[NUM_FILE_DESCRIPTORS] = { 0, 0, 0, 0,
                                                     0, 0, 0, 0};

/********************************************************************
 * initFileDescriptors - init the file descriptors                  *
 * prerequisites:  should only be called once per program           *
 *                 (otherwise devices will be opened multiple times *
 ********************************************************************/
int
initFileDescriptors( void )
{
  int fd;

  fd = open( "/dev/crypto", O_RDWR );

  if( fd == -1 )
    return( ERROR );

  fileDescriptor[ FD_XCRYPTO ] = fd;

  fd = open( "/dev/pka", O_RDWR );

  if( fd == -1 )
    return( ERROR );

  fileDescriptor[ FD_PKA ] = fd;

  fd = open( "/dev/skch", O_RDWR );

  if( fd == -1 )
    return( ERROR );

  fileDescriptor[ FD_DES ] = fd;
  fileDescriptor[ FD_SHA ] = fd;
  fileDescriptor[ FD_AES ] = fd;

  fd = open( "/dev/hwrng", O_RDONLY );

  if( fd == -1 )
    return( ERROR );

  fileDescriptor[ FD_HWRNG ] = fd;

  fd = -1;
  fileDescriptor[ FD_OA ] = fd;

  return OK;
}

int 
getFileDescriptor( int device_driver )
{
 
  if( device_driver >= NUM_FILE_DESCRIPTORS )
    return -2;

  return fileDescriptor[ device_driver ];
}

#endif

void createDummyResponse( responseStruct *pResponse, int errorCode, int pid )
{
  static unsigned char dummy[8] = { 1,2,3,4,5,6,7,8 };
  dummyHdr_t dummyHdr;
  memset( &dummyHdr, 0x00, sizeof( dummyHdr_t ) );
  dummyHdr.pid = pid;
  dummyHdr.len = sizeof( dummyHdr_t );
  pResponse->status = errorCode;
  pResponse->headerLength = sizeof( dummyHdr_t );
  memcpy( pResponse->header, &dummyHdr, sizeof( dummyHdr_t ) );
  pResponse->dataLength = sizeof( dummy );
  memcpy( pResponse->data, dummy, sizeof(dummy) );
  pResponse->userDef = 0;
  return;
}
