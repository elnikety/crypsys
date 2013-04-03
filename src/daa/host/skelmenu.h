/*********************************************************/
/* Host side header file for skeleton menu related items */
/*********************************************************/

#ifndef _SKELMENU_H_
#define _SKELMENU_H_

#ifndef _XC_HOST_H_
  #include "xc_host.h" /* for xcAdapterHandle_t */
#endif

/* number of servers available */
/* note one server can be running as multiple threads on the card */
#define SERVERS 8 
/* choice on menu to exit program */
#define EXITPROGRAM 8

/* prints standard menu of options to stdout */
void 
printMenu( void );

/* does a request */
void 
do_request( int                 requestID, 
            xcAdapterHandle_t * pAdapterHandle );

/* reads an integer from stdin */
int  
read_safe_integer( void );

/* types of servers available */
static const enum serverTypes 
{ 
  adptserv,  
  desserv, 
  hshserv,
  limserv, 
  pkaserv, 
  rngserv,  
  model,
  aesserv   
}serverTypes;
  
/* pka types */
static const enum pkaTypes 
{ 
  generateDSA, 
  requestDSAsign, 
  verifyRequest,
  requestRSAsign, 
  encryptRSA, 
  decryptRSA 
}pkaTypes;

/* types for des operations */
static const enum desTypes 
{ 
  desEncrypt8, 
  desDecrypt8, 
  desEncrypt,
  desDecrypt, 
  desMACGenerate, 
  desWrap,
  desUnwrap, 
  CDMFEncrypt, 
  CDMFDecrypt,
  RawCDMFEncrypt, 
  RawCDMFDecrypt 
}desTypes;

#endif
