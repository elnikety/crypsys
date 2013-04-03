/*************************************************/
/* Header for PKA Host internal helper functions */
/*************************************************/

#ifndef _PKA_HOST_H_
#define _PKA_HOST_H_

int 
getDSAKeyGenerateInput( pkaReqHdr_t * pPKAReqHdr,
                        char        * DESKeyFileName );

int 
getRSAKeyGenerateInput( pkaReqHdr_t * pPKAReqHdr,
                        char        * RSAKeyFileName );

int 
getRSAEncryptDecryptData( pkaReqHdr_t * pPKAReqHdr,
                          int           request,
                          char        * outputFileName );

int 
getDSASignVerifyData( pkaReqHdr_t * pPKAReqHdr,
                      int           request,
                      char        * outputFileName );

int 
processRSAKeyGenerateOutput( char * pReplyBuf,
                             int    replyLength,
                             char * outputFileName );

int 
processDSAKeyGenerateOutput( char * pReplyBuf,
                             int    replyLength,
                             char * outputFileName );

int 
processRSAEncryptDecryptOutput( char * pReplyBuf,
                                int    replyLength,
                                char * outputFileName,
                                int    request );

int 
processDSASignVerifyOutput( char * pReplyBuf,
                            int    replyLength,
                            char * outputFileName,
                            int    request,
                            int    status );

int 
prettyPrintOffCardDSAKeyToken( offCardDSAToken_t * pOffCardDSAToken );

int  
prettyPrintOffCardRSAKeyToken( offCardRSAToken_t * pOffCardRSAToken );

#endif
