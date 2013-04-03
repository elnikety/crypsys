/***********************************************************************
 * pkaHost.c - Host Skeleton sample program.                           *
 *             This program is an example of PKA services as part of   *
 *             a menu of options (skelhost.c is the main server)       *
 *                                                                     *
 ***********************************************************************/
/* PKA Host pieces of skeleton example */

#include <stdio.h>   /* printf et al */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef NT_ON_I386
  #include <windows.h>
#endif

#include "xc_types.h" /* xCrypto types */
#include "xc_host.h"  /* xCrypto host functions */

#include "skelServers.h"
#include "pkaserv.h"
#include "pkaHost.h"
#include "skelcmn.h"
#include "skelmenu.h"
#include "../../rte/shared/util.h"

int
getUserRequest( void );

void
do_pkaserv( xcAdapterHandle_t * pAdapterHandle )
{
  unsigned char       dummyBuf[8];    /* dummy buffer to grab stray input  */
  pkaReqHdr_t       * pPKAReqHdr;     /* pointer to a pka request header   */
  pkaRepHdr_t         pkaRepHdr;      /* pka server reply header from card */
  xcRB_t              xcRequestBlock; /* xCrypto request block             */
  char              * pReplyBuf;      /* reply Buffer from card            */
  int                 request;        /* user requested operation          */
  int                 rc = 0;         /* return code for various functions */
  char *              outputFileName; /* name of file to open              */
  int                 replyLength;    /* length of card reply in bytes     */

  /* dynamically allocate memory */
  outputFileName = (char*) malloc( 80 );
  pReplyBuf = (char *) malloc( MAX_PADDED_PKA_TOKEN_LENGTH );
  pPKAReqHdr = (pkaReqHdr_t*) malloc( sizeof( pkaReqHdr_t ) );

  /* check for malloc failures, end if any malloc failed */
  if( outputFileName == NULL ||
      pReplyBuf      == NULL ||
      pPKAReqHdr     == NULL )
  {
    if( outputFileName )
      free( outputFileName );
    if( pReplyBuf )
      free( pReplyBuf );
    if( pPKAReqHdr )
      free( pPKAReqHdr );

    printf( "Malloc Failure in pkaHost.c\n" );

    return;
  }

  /* initialize variables */
  memset( dummyBuf, 0x00, sizeof( dummyBuf ) );
  memset( pPKAReqHdr, 0x00, sizeof( pkaReqHdr_t ) );
  memset( &pkaRepHdr, 0x00, sizeof( pkaRepHdr_t ) );
  memset( &xcRequestBlock, 0x00, sizeof( xcRB_t ) );
  memset( outputFileName, 0x00, 80 );
  memset( pReplyBuf, 0x00, MAX_PADDED_PKA_TOKEN_LENGTH );

  /* find out what the user wants to do */
  request = getUserRequest( );

  /* return to main menu check */
  if( request == 6 )
  {
    if( outputFileName )
      free( outputFileName );
    if( pReplyBuf )
      free( pReplyBuf );
    if( pPKAReqHdr )
      free( pPKAReqHdr );
    return;
  }

  /* eat \n sitting on stdin */
  fgets( (char *)dummyBuf, sizeof( dummyBuf ), stdin );

  pPKAReqHdr->options = HTOAL( request );

  /* grab input as appropriate */
  switch( request )
  {
    case DSA_KEYGEN:
      rc = getDSAKeyGenerateInput( pPKAReqHdr,
                                   outputFileName );
    break;

    case RSA_KEYGEN:
      rc = getRSAKeyGenerateInput( pPKAReqHdr,
                                   outputFileName );
    break;

    case DSA_SIGN:
    case DSA_VERIFY:
      rc = getDSASignVerifyData( pPKAReqHdr,
                                 request,
                                 outputFileName );
    break;


    case RSA_ENC:
    case RSA_DEC:
      rc = getRSAEncryptDecryptData( pPKAReqHdr,
                                     request,
                                     outputFileName );
    break;
  }

  /* don't go on if we had trouble gathering inputs */
  if( rc )
  {
    if( outputFileName )
      free( outputFileName );
    if( pReplyBuf )
      free( pReplyBuf );
    if( pPKAReqHdr )
      free( pPKAReqHdr );
    printf( "Error!  Inputs for PKASERV are invalid. Please try again.\n" );

    return;
  }

  /* set up xC Request block items */
  /* we will always be sending a header and expecting a char * buffer in return*/
  xcRequestBlock.AgentID     = HTOAS( skeletonAgentID );
  xcRequestBlock.UserDefined = HTOAL( PKASERV_PKA );

  xcRequestBlock.RequestControlBlkLength = sizeof( pkaReqHdr_t );
  xcRequestBlock.RequestControlBlkAddr   = (unsigned char*)pPKAReqHdr;

  xcRequestBlock.RequestDataLength  = 0;
  xcRequestBlock.RequestDataAddress = NULL;

  xcRequestBlock.ReplyControlBlkLength = sizeof( pkaRepHdr_t );
  xcRequestBlock.ReplyControlBlkAddr   = (unsigned char *)&pkaRepHdr;

  xcRequestBlock.ReplyDataLength =  MAX_PADDED_PKA_TOKEN_LENGTH;
  xcRequestBlock.ReplyDataAddr   = (unsigned char*)pReplyBuf;


  /* call the xcrypto card, wait for result */
  if( ( rc = xcRequest( *pAdapterHandle, &xcRequestBlock ) != 0 ) )
  {
    printf( "xcRequest failed rc = %d\n", rc );
    /* set request to bypass output printing */
    request = -1;
  }

  printf( "Request Returned, status = 0x%lx\n",
          ATOHL( xcRequestBlock.Status ) );

  printf( "Process ID of servicing thread = 0x%lx\n",
          ATOHL( pkaRepHdr.pid ) );

  printf( "\n" );
  replyLength = ATOHL( pkaRepHdr.replyLength );

  switch( request )
  {
    case DSA_KEYGEN:

      processDSAKeyGenerateOutput( pReplyBuf,
                                   replyLength,
                                   outputFileName );
    break;

    case RSA_KEYGEN:

      processRSAKeyGenerateOutput( pReplyBuf,
                                   replyLength,
                                   outputFileName );

    break;

    case RSA_ENC:
    case RSA_DEC:

      processRSAEncryptDecryptOutput( pReplyBuf,
                                      replyLength,
                                      outputFileName,
                                      request );
    break;

    case DSA_SIGN:
    case DSA_VERIFY:
      
      rc = processDSASignVerifyOutput( pReplyBuf,
                                  replyLength,
                                  outputFileName,
                                  request,
                                  xcRequestBlock.Status );
    break;

    default:
      printf( "xcRequest Error...No Output Printed\n" );
    break;
  }

  printf( "\n" );

  if( outputFileName )
    free( outputFileName );
  if( pReplyBuf )
    free( pReplyBuf );
  if( pPKAReqHdr )
    free( pPKAReqHdr );

  return;

}


int
getDSAKeyGenerateInput( pkaReqHdr_t * pPKAReqHdr,
                        char        * DESKeyFileName )
{
  /* We need to find prime_p_bit size, and filename to store output*/
  unsigned char dummyBuf[8];
  int           prime_p_bit_size;

  /*****************************************************************/
  /* for DSA Key Generation, I allow the user to enter the size of */
  /* prime p in bits, and the name of a file to store the token in */
  /* more options could be specified here, but this suffices for   */
  /* the purposes of this simple example                           */
  /*****************************************************************/

  printf( "DSA Key Generation\n" );

  /* make sure the user enters prime p bit size between 512 and 1024 */
  /* (inclusive) and a multiple of 64 bytes                          */
  do
  {
    printf( "Enter Prime P Size in Bits\n" );
    memset( dummyBuf, 0x00, sizeof( dummyBuf ) );
    fgets( (char *)dummyBuf, sizeof( dummyBuf ), stdin );
    prime_p_bit_size = atoi( (char *)dummyBuf );
  }while( prime_p_bit_size < 512 || prime_p_bit_size > 1024 ||
         ( prime_p_bit_size % 64 ) != 0 );

  /* indicate bit size of key to generate on card */
  pPKAReqHdr->bitSize     = HTOAL( prime_p_bit_size );
  pPKAReqHdr->tokenLength = HTOAL( MAX_PADDED_PKA_TOKEN_LENGTH );

  /* get the name of the file to store the output token */
  printf( "Enter Filename to Store Generated DSA Key Token\n" );

  fgets( DESKeyFileName, 80, stdin );
  DESKeyFileName[ strlen(DESKeyFileName) > 0 ?  strlen(DESKeyFileName)  -1 : 0 ] = 0;

  return 0;
}

int
getRSAKeyGenerateInput( pkaReqHdr_t * pPKAReqHdr,
                        char        * RSAKeyFileName )
{
  /* need to grab modulus bit size, and filename to store output */
  int           n_bit_size;/* modulus size in bits */
  unsigned char dummyBuf[8];

  /* For RSA key generation, I allow the user to enter the size of the */
  /* modulus N, in bits, and the name of the file to store the token in*/
  /* More options could be specified here (for instance e is hard coded*/
  /* to 65537) but this suffices for the purposes of this simple example*/
  /* furthermore, one would not want to export private keys in the clear*/
  /* from the card                                                      */

  printf( "RSA Key Generation\n" );

  /* NOTE:  Modulus Bit size limited to 2048 for this example.  
   * If a key larger than 2048 bits is generated, the device driver 
   * timeout may need to be lengthened from the default
   */

  /* make sure the user enters a moduls bit size between 512 and 2048 */
  /* (inclusive) and is a multiple of 64 bytes                        */
  do
  {
    printf( "Enter Modulus (N) Size in Bits\n" );
    memset( dummyBuf, 0x00, sizeof( dummyBuf ) );
    fgets( (char *)dummyBuf, sizeof( dummyBuf ), stdin );
    n_bit_size = atoi( (char *)dummyBuf );
  }while( n_bit_size < 512 || n_bit_size > 2048 ||
         ( n_bit_size % 64 ) != 0  );

  /* set bit size of key to generate */
  pPKAReqHdr->bitSize = HTOAL( n_bit_size );
  pPKAReqHdr->tokenLength = HTOAL( MAX_PADDED_PKA_TOKEN_LENGTH );

  /* ask user where they want to store the key token for possible future */
  /* use in an encrypt/decrypt operation                                 */
  printf( "Enter Filename to Store Generated RSA KeyToken\n" );
  fgets( RSAKeyFileName, 80, stdin );
  RSAKeyFileName[ strlen(RSAKeyFileName) > 0 ?  strlen(RSAKeyFileName)  -1 : 0 ] = 0;

  return 0;
}

/****************************/
/****************************/
/****************************/

int
getRSAEncryptDecryptData( pkaReqHdr_t * pPKAReqHdr,
                          int           request,
                          char        * outputFileName )
{
  int                 rc;
  struct stat         fileStat; /* used to grab file size in bytes */
  FILE              * fp;       /* file pointer */
  offCardRSAToken_t * pOffCardRSAToken;

  /* For Encrypt and Decrypt Operations, we Need to read in the key to */
  /* encrypt or decrypt with, as well as a data file containing encrypted */
  /* or decrypted text.  For simplicity's sake, it is required that the length */
  /* of data to be encrypted or decrypted should be the same as the modulus length */
  /* of the encrypting or decrypting key (in bytes) */

  if( request == RSA_ENC )
  {
    printf( "RSA Encryption\n" );
    printf( "Enter Filename for the Encrypting Key\n" );
  }
  else
  {
    printf( "RSA Decryption\n" );
    printf( "Enter Filename for the Decrypting Key\n" );
  }

  fgets( outputFileName, 80, stdin );

  outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;
  rc = stat( outputFileName, &fileStat );

  if( rc != 0 )
  {
    printf( "stat of file %s failed.\n", outputFileName );
    return rc;
  }

  if( ( fp = fopen( outputFileName, "rb" ) ) == NULL )
  {
    printf( "Error...could not open %s \n", outputFileName );
    return rc;
  }

  fread( pPKAReqHdr->keyToken, fileStat.st_size, 1, fp );

  if( fp )
    fclose( fp );

  pPKAReqHdr->tokenLength = HTOAL( fileStat.st_size );

  /*
  * we're going to assume that the user wants to encrypt a file
  * which is the same length as the modulus (in bytes) of the
  * encrypting / decrypting key
  */

  memset( &fileStat, 0x00, sizeof( struct stat ) );
  memset( outputFileName, 0x00, 80 );

  printf( "Enter Name of File To Encrypt/Decrypt\n" );
  fgets( outputFileName, 80, stdin );
  outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;

  rc = stat( outputFileName, &fileStat );

  if( rc != 0 )
  {
    printf( "stat of file %s failed.\n", outputFileName );
    return rc;
  }

  if( ( fp = fopen( outputFileName, "rb" ) ) == NULL )
  {
    printf( "Error...could not open %s \n", outputFileName );
    return -1;
  }

  fread( pPKAReqHdr->data, fileStat.st_size, 1, fp );

  if( fp )
    fclose( fp );

  pOffCardRSAToken = (offCardRSAToken_t *)pPKAReqHdr->data;


  pPKAReqHdr->dataLength = HTOAL( fileStat.st_size );

  /* we need to print out encrypted/decrypted text to a file */
  memset( outputFileName, 0x00, sizeof( outputFileName ) );
  printf( "Enter Name of File to Save Encrypted/Decrypted Data\n" );
  fgets( outputFileName, 80, stdin );
  outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;

  return rc;
}

int
getDSASignVerifyData( pkaReqHdr_t * pPKAReqHdr,
                      int           request,
                      char        * outputFileName )
{
  int                 rc;
  FILE              * fp;
  offCardDSAToken_t * pOffCardDSAToken;
  struct stat         fileStat;

  if( request == DSA_SIGN )
    printf( "DSA Sign\n" );
  else
    printf( "DSA Verify\n" );

  /* 20 bytes to sign/verify */
  printf( "Enter Filename for Signing Key\n" );

  fgets( outputFileName, 80, stdin );

  outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;
  rc = stat( outputFileName, &fileStat );

  if( rc != 0 )
  {
    printf( "stat of file %s failed.\n", outputFileName );
    return rc;
  }

  if( ( fp = fopen( outputFileName, "rb" ) ) == NULL )
  {
    printf( "Error...could not open %s \n", outputFileName );
    return -1;
  }

  fread( pPKAReqHdr->keyToken, fileStat.st_size, 1, fp );

  if( fp )
    fclose( fp );

  pOffCardDSAToken = (offCardDSAToken_t *)pPKAReqHdr->keyToken;

  pPKAReqHdr->tokenLength = HTOAL( fileStat.st_size );

  printf( "Enter Filename Containing 20 bytes of Data To Sign/Verify\n" );
  memset( outputFileName, 0x00, 80 );

  fgets( outputFileName, 80, stdin );

  outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;
  rc = stat( outputFileName, &fileStat );

  if( rc != 0 )
  {
    printf( "stat of file %s failed.\n", outputFileName );
    return rc;
  }

  if( ( fp = fopen( outputFileName, "rb" ) ) == NULL )
  {
    printf( "Error...could not open %s \n", outputFileName );
    return -1;
  }

  fread( pPKAReqHdr->data, fileStat.st_size, 1, fp );

  if( fp )
    fclose( fp );

  pPKAReqHdr->dataLength = HTOAL( fileStat.st_size );


  /* if request is for a verify, need to grab signature */

  if( request == DSA_VERIFY )
  {
    printf( "Enter Filename Containing Signature to be Verified\n" );

    memset( outputFileName, 0x00, 80 );
    fgets( outputFileName, 80, stdin );

    outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;
    rc = stat( outputFileName, &fileStat );

    if( rc != 0 )
    {
      printf( "stat of file %s failed.\n", outputFileName );
      return rc;
    }

    if( ( fp = fopen( outputFileName, "rb" ) ) == NULL )
    {
      printf( "Error...could not open %s \n", outputFileName );
      return -1;
    }

    fread( pPKAReqHdr->signature, fileStat.st_size, 1, fp );

    if( fp )
      fclose( fp );

    pPKAReqHdr->signatureLength = HTOAL( fileStat.st_size );
  }

  if( request == DSA_SIGN )
  {
    /* get the name of the file to store the output token */
    memset( outputFileName, 0x00, 80 );
    printf( "Enter Filename to Store Generated DSA Signature\n" );
    fgets( outputFileName, 80, stdin );
    outputFileName[ strlen(outputFileName) > 0 ?  strlen(outputFileName)  -1 : 0 ] = 0;
  }

  return rc;
}


int
processRSAKeyGenerateOutput( char * pReplyBuf,
                             int    replyLength,
                             char * outputFileName )
{
  FILE * fp;

  /* print the token */
  prettyPrintOffCardRSAKeyToken( (offCardRSAToken_t *)pReplyBuf );

  /* write token to file */
  if( ( fp = fopen( outputFileName, "wb" ) ) == NULL )
  {
    printf( "Error...could not open %s for writing\n", outputFileName );
    return -1;
  }

  fwrite( pReplyBuf,
          replyLength,
          1,
          fp );

  printf( "Closing file %s\n", outputFileName );

  if( fp )
    fclose( fp );

  return 0;
}


int
processDSAKeyGenerateOutput( char * pReplyBuf,
                             int    replyLength,
                             char * outputFileName )
{
  int    rc = 0;
  FILE * fp = NULL;

  /* print out the token */
  prettyPrintOffCardDSAKeyToken( (offCardDSAToken_t *)pReplyBuf );

  if( ( fp = fopen( outputFileName, "wb" ) ) == NULL )
  {
    printf( "Error...could not open %s for writing\n", outputFileName );
    return -1;
  }

  fwrite( pReplyBuf,
          replyLength,
          1,
          fp );

  printf( "Closing file %s\n", outputFileName );

  if( fp )
    fclose( fp );

  return rc;
}

int
processRSAEncryptDecryptOutput( char * pReplyBuf,
                                int    replyLength,
                                char * outputFileName,
                                int    request )
{
  int rc = 0;
  int i = 0;/* loop control variable */
  FILE *fp = NULL;

  if( request == RSA_ENC )
  {
    printf( "Processed Data\n" );
    for( i = 0; i < replyLength; i++ )
    {
      if( i != 0 && i % MAX_LINE_WIDTH == 0 )
        printf( "\n" );
      printf( "%02x ", *pReplyBuf + i );
    }
  }

  printf( "\n" );

  if( (fp = fopen( outputFileName, "wb" ) ) == NULL )
  {
    printf( "Error -> Could not open %s \n", outputFileName );
    return -1;
  }

  fwrite( pReplyBuf,
          replyLength,
          1,
          fp );

  if( fp )
    fclose(fp);

  if( request == RSA_ENC )
    printf( "Encrypted Data saved in %s\n", outputFileName );
  else
    printf( "Decrypted Data saved in %s\n", outputFileName );


  return rc;
}

int
processDSASignVerifyOutput( char * pReplyBuf,
                            int    replyLength,
                            char * outputFileName,
                            int    request,
                            int    status )
{
  int    rc = 0;
  FILE * fp = NULL;
  
  if( request == DSA_SIGN )
  {
    if( ATOHL(status) != PKA_OK )
    {
      printf( "Signature Not Properly Generated, rc = 0x%lx\n",
              ATOHL(status) );
    }

    printf( "Signature Complete!  Results in %s\n", outputFileName );

    if( (fp = fopen( outputFileName, "wb" ) ) == NULL )
    {
      printf( "Error -> Could not open %s \n", outputFileName );
      return -1;
    }

    fwrite( pReplyBuf,
            replyLength,
            1,
            fp );

    if( fp )
      fclose(fp);
  }
  else
  {
    if( ATOHL(status )  == PKA_OK )
      printf( "Signature Verified!\n" );
    else
      printf( "Signature Not Verified. rc = 0x%lx\n",
              ATOHL(status) );
  }

  return rc;
}

/* utility function to print DSA token */
int
prettyPrintOffCardDSAKeyToken( offCardDSAToken_t * pOffCardDSAToken )
{

  int i = 0;

  printf( "Generated DSA Key Token:\n" );
  printf( "key_type = %ld\n",
          ATOHL( pOffCardDSAToken->key_type ) );
  printf( "key_token_length (in bytes) = %ld\n",
          ATOHL( pOffCardDSAToken->key_token_length ) );

  printf( "prime_p_bit_length = %ld\n",
          ATOHL( pOffCardDSAToken->prime_p_bit_length ) );

  printf( "p_length = %ld\n",
           ATOHL( pOffCardDSAToken->p_length ) );

  printf( "g_length = %ld\n",
           ATOHL( pOffCardDSAToken->g_length ) );

  printf( "x_length = %ld\n",
           ATOHL( pOffCardDSAToken->x_length ) );

  printf( "y_length = %ld\n",
           ATOHL( pOffCardDSAToken->y_length ) );

  printf( "q_length = %ld\n",
           ATOHL( pOffCardDSAToken->q_length ) );

  printf( "\n\nP\n" );

  for( i = 0; i < ATOHL( pOffCardDSAToken->p_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
             *((unsigned char*)pOffCardDSAToken  +
            sizeof( offCardDSAToken_t ) -1 +
            ATOHL( pOffCardDSAToken->p_offset ) + i ));

  }

  printf( "\n\nG\n" );

  for( i = 0; i < ATOHL( pOffCardDSAToken->g_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardDSAToken +
            sizeof( offCardDSAToken_t ) -1 +
            ATOHL( pOffCardDSAToken->g_offset ) + i ) );

  }

  printf( "\n\nX\n" );
  for( i = 0; i < ATOHL( pOffCardDSAToken->x_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardDSAToken +
            sizeof( offCardDSAToken_t ) -1 +
            ATOHL( pOffCardDSAToken->x_offset ) + i ));

  }

  printf( "\n\nY\n" );

  for( i = 0; i < ATOHL( pOffCardDSAToken->y_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardDSAToken +
            sizeof( offCardDSAToken_t ) -1 +
            ATOHL( pOffCardDSAToken->y_offset ) + i ));

  }

  printf( "\n\nQ\n" );

  for( i = 0; i < ATOHL( pOffCardDSAToken->q_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardDSAToken +
            sizeof( offCardDSAToken_t ) -1 +
            ATOHL( pOffCardDSAToken->q_offset ) + i ));
  }

  printf( "\n\n" );

  return 0;
}

/* utility function to print RSA key token */
int
prettyPrintOffCardRSAKeyToken( offCardRSAToken_t * pOffCardRSAToken )
{
  int i = 0;
  printf( "RSA Key Generation Complete\n" );

  printf( "RSA Key Token\n" );
  printf( "type = %ld\n",
          ATOHL( pOffCardRSAToken->type ) );

  printf( "tokenLength (in bytes) = %ld\n",
          ATOHL( pOffCardRSAToken->tokenLength ) );

  printf( "n_BitLength = %ld\n",
          ATOHL( pOffCardRSAToken->n_BitLength ) );

  printf( "n_Length (in bytes) = %ld\n",
          ATOHL( pOffCardRSAToken->n_Length ) );

  printf( "e_Length = %ld\n",
          ATOHL( pOffCardRSAToken->e_Length ) );

  printf( "p_Length ( or d_Length ) = %ld\n",
          ATOHL( pOffCardRSAToken->x.p_Length ) );

  printf( "q_Length = %ld\n",
          ATOHL( pOffCardRSAToken->q_Length ) );

  printf( "dpLength = %ld\n",
          ATOHL( pOffCardRSAToken->dpLength ) );

  printf( "dqLength = %ld\n",
          ATOHL( pOffCardRSAToken->dqLength ) );

  printf( "apLength = %ld\n",
          ATOHL( pOffCardRSAToken->apLength ) );

  printf( "aqLength = %ld\n",
          ATOHL( pOffCardRSAToken->aqLength ) );

  printf( "r_Length = %ld\n",
          ATOHL( pOffCardRSAToken->r_Length ) );

  printf( "r1Length = %ld\n",
          ATOHL( pOffCardRSAToken->r1Length ) );

  printf( "\n\nN \n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->n_Length); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->n_Offset ) + i -1 ));

  }

  printf( "\n\nE\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->e_Length); i++  )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->e_Offset ) + i -1 ));

  }

  printf( "\nP (or D)\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->x.p_Length); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->y.p_Offset ) + i -1));

  }

  printf( "\nQ\n" );

  for( i = 0; i < ATOHL( pOffCardRSAToken->q_Length ); i++ )
  {
    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->q_Offset ) + i -1 ));

    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
  }

  printf( "\nDP\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->dpLength ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->dpOffset ) + i -1));

  }

  printf( "\nDQ\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->dqLength ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->dqOffset ) + i -1));

  }

  printf( "\n AP \n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->apLength ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->apOffset ) + i -1 ));

  }

  printf( "\nAQ\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->aqLength ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->aqOffset ) + i -1));

  }

  printf( "\nR\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->r_Length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->r_Offset ) + i -1 ));

  }

  printf( "\nR1\n" );
  for( i = 0; i < ATOHL( pOffCardRSAToken->r1Length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );

    printf( "%02x ",
            *((unsigned char*)pOffCardRSAToken +
            sizeof( offCardRSAToken_t ) +
            ATOHL( pOffCardRSAToken->r1Offset ) + i -1));

  }

  printf( "\n" );
  return 0;
}


/* utility function to print DSA Signature Token */
void
prettyPrintOffCardDSASignatureToken( offCardDSASignature_t * pOffCardDSASignature )
{
  int i = 0;

  printf( "Signature:\n" );
  printf( "signature_token_length = %ld\n",
          ATOHL( pOffCardDSASignature->signature_token_length ) );
  printf( "r_length = %ld\n",
          ATOHL( pOffCardDSASignature->r_length ) );
  printf( "s_length = %ld\n",
          ATOHL( pOffCardDSASignature->s_length ) );

  printf( "r = \n" );
  for( i = 0; i < ATOHL( pOffCardDSASignature->r_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
    printf( "%02x ",
        *((unsigned char*)pOffCardDSASignature +
        ATOHL( pOffCardDSASignature->r_offset ) + i ));
  }

  printf( "\ns = \n" );
  for( i = 0; i < ATOHL( pOffCardDSASignature->s_length ); i++ )
  {
    if( i != 0 && i % MAX_LINE_WIDTH == 0 )
      printf( "\n" );
    printf( "%02x ",
        *((unsigned char*)pOffCardDSASignature +
        ATOHL( pOffCardDSASignature->s_offset ) + i ));
  }
  return;
}

int
getUserRequest( void )
{

  int request = -1;

  /* determine what user wants to do */
  printf( "---------------------------------------\n" );
  printf( " DSA and RSA key functions\n" );
  printf( "---------------------------------------\n" );

  while( ( request < 0 ) || ( request > 6 ) )
  {
    printf( "MENU:\n"
            "0.) Generate DSA Keypair.\n"
            "1.) Generate DSA Signature.\n"
            "2.) Verify a Digital Signature.\n"
            "3.) Generate RSA Keypair.\n"
            "4.) Encrypt using RSA.\n"
            "5.) Decrypt using RSA.\n\n"
            "6.) Return to Main Menu\n"
            "Choice===> " );
    request = read_safe_integer( );
  }

  return request;
}

