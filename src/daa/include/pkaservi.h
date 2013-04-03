/* internal header for pka server */
#if !defined(_pkaservi_h_)
#define _pkaservi_h_

#include "xc_types.h"

#include "skelcmn.h"
#include "pkaserv.h"
#include "adptservi.h"

/* Main function for PKA service thread */
void  
pkaServer( xcVirtualPacket_t * pVPkt, 
           responseStruct    * pResponse );

/* used to convert an off card dsa token type into an on card */
/* dsa token type, so the 4765 can understand the token */
int 
convertFromOffCardDSAToken( offCardDSAToken_t * pOffCardDSAToken,
                            xcDSAKeyToken_t   * pDSAKeyToken );

/* used to convert an off card rsa token type into an on card */
/* rsa token type, so the 4765 can understand the token */
int 
convertFromOffCardRSAToken( offCardRSAToken_t * pOffCardRSAToken,
                            xcRsaKeyToken_t   * pRSAKeyToken );

/* converts a DSA token stored on the card to an offCardDSAToken_t */
/* which can then be passed to the host */
int 
convertToOffCardDSAToken( xcDSAKeyToken_t   * pDSAKeyToken,
                          offCardDSAToken_t * pOffCardDSAToken );


/* converts a RSA token stored on the card to an offCardRSAToken_t */
/* which can then be passed to the host */
int 
convertToOffCardRSAToken( xcRsaKeyToken_t   * pRSAKeyToken,
                          offCardRSAToken_t * pOffCardRSAToken );

/* initializes an xCrypto RSA token provided the token has been properly allocated */
int 
initializexCryptoRSAToken( xcRsaKeyToken_t * pRSAKeyToken,
                           int               n_bit_size );

/* initializes an xCrypto DSA token provided the token has been properly allocated */
int 
initializexCryptoDSAToken( xcDSAKeyToken_t * pDSAKeyToken,
                           int               prime_p_bit_size );

void 
RSAKeyGenerate( responseStruct *, int );
  
void 
DSAKeyGenerate( responseStruct * pResponse, 
                int              bitSize );

void 
RSAKeyGenerate( responseStruct * pResponse, 
                int              bitSize );

void 
RSAEncryptOrDecrypt( responseStruct * pResponse,
                     int              userRequest,
                     unsigned char  * pKey,
                     unsigned char  * pData,
                     int              dataLength );

void  
DSASignVerify( responseStruct * pResponse,
               unsigned char  * pKey,
               unsigned char  * pData,
               unsigned long    dataLength,
               unsigned char  * pSignature,
               unsigned long    signatureLength,
               int              userRequest );

#endif
