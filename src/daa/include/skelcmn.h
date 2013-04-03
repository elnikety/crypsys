/* common headers for skeleton samples */
#if !defined(_skelcmn_h_)
#define _skelcmn_h_

#include "xc_types.h"

#define MAX_LINE_WIDTH 24

#pragma pack(1)
typedef struct dummyHdr_t
{
  int len;
  int pid; 
  /* pad to make struct at least 64 bytes */
  char dummy[ 64 - ( 2 * sizeof( int ) ) ];
}dummyHdr_t;
#pragma pack()

#pragma pack(1)
typedef struct responseStruct
{
  /* length of header in bytes */
  int    headerLength;
  /* pointer to header buffer */
  void * header;
  /* length of data in bytes */
  int    dataLength;
  /* pointer to data buffer */
  void * data;
  /* status of request */
  int    status;
  /* user defined field */
  int    userDef;
  /* pad to make struct at least 64 bytes */  
  char   pad[40];
}responseStruct;
#pragma pack()

const static uint16_t  skeletonAgentID =  0x534B; /* "SK" for "SK"eleton */

void 
createDummyResponse( responseStruct * pResponse, 
                     int              errorCode, 
                     int              pid );

#define NO_FILE_DESCRIPTOR 0   // Indicates no File Descriptor required by  /* n11 */
                               // called device driver procedure.

// Device Drivers Supported
#define FD_XCRYPTO         1   // Xcrypto Manager
#define FD_PKA             2   // PKA Manager
#define FD_DES             3   // DES Manager
#define FD_SHA             4   // SHA Manager
#define FD_HWRNG           5   // Hardware Random Number Gen. Manager
#define FD_OA              6   // Outbound Authentication Manager
#define FD_AES             7   // AES Manager

#define NUM_FILE_DESCRIPTORS 8 // Number of file descriptors

/* returns a file descriptor for any of the above device drivers */
int 
getFileDescriptor( int device_driver );

int
initFileDescriptors( void );

/* converts a text string to a hex array */
int 
textStringToHexArray( char * textBuf,
                      long textBufLength,/* in bytes */
                      char * hexArray,
                      long   hexArrayLength );/* in bytes */

/* converts a character to a hex nibble */
char 
charToHexNibble( char ch );

#endif
