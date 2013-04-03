/*********************************************************************** 
 * hostUtils.c - Skeleton host side utilities for driver program.      * 
 *               These functions assist with conversion for the        * 
 *               various skeleton functions                            * 
 *                                                                     * 
 ***********************************************************************/

#include <stdio.h>  /* printf et al              */
#include <stdlib.h> /* for std library functions */
#include <string.h> /* for memset et al          */
#include <ctype.h>  /* for isxdigit              */

#include "skelcmn.h"

/* it is assumed that each hex digi 0-9 a-f is 1 nibble */
/* so 1 byte is composed of 2 nibbles, i.e. 1 byte of 0 is */
/* represented by 00, not 0.  */
int textStringToHexArray( char * textBuf,
                          long   textBufLength,
                          char * hexArray,
                          long   hexArrayLength )
{
  int textIndex = 0, hexIndex = 0;
  char ch = 0;
  char * workingBuffer = NULL;
  int    workingBufferLength = 0;
  int    workingBufferIndex = 0;

  /* check for initial validity of inputs */
  if( textBuf == NULL || hexArray == NULL || textBufLength <=0 ||
      hexArrayLength <= 0 )
    return -1;

  workingBuffer = (char *) malloc( textBufLength );

  if( workingBuffer == NULL )
    return -2;

  memset( workingBuffer, 0x00, textBufLength );

  /* loop through array, looking for characters */
  for( textIndex = 0; textIndex < textBufLength; textIndex++ )
  {
    /* skip spaces */
    ch = textBuf[textIndex];

    if( isspace( ch ) )
      continue;

    if( ch == 0 )
      break;

    if( isxdigit(ch) == 0 )
    {
      if( workingBuffer ) 
        free( workingBuffer );
      return -3;
    }
    //ok, now we have a valid hex digit, stick it into array
    workingBuffer[workingBufferLength] = (ch);
    workingBufferLength++;
  }

  if( hexArrayLength < ( workingBufferLength + 1 ) / 2 )
  {
    if( workingBuffer )
      free( workingBuffer );
    return -4;//not enough space
  }

  /* now we have a working buffer, containing all the hex digits
   * compress this into a byte array and stick it in hexArray
   * workingBuffer[i] contains the text value of a hex nibble
   * convert to hex values
   */
  workingBufferIndex =  hexIndex = 0;

  while( workingBufferIndex < workingBufferLength )
  {
    if( workingBufferIndex == 0 && ( workingBufferLength % 2 ) )
    {
      hexArray[hexIndex] = charToHexNibble( workingBuffer[workingBufferIndex] );
      workingBufferIndex++;
    }
    else
    {
      hexArray[hexIndex] = ( charToHexNibble(workingBuffer[workingBufferIndex] ) << 4 ) |
                            charToHexNibble(workingBuffer[workingBufferIndex+1] );
      workingBufferIndex += 2;
    }

    hexIndex++;
  }

  /* don't forget to free memory */
  if( workingBuffer )
    free( workingBuffer );

  return hexIndex;
}

char 
charToHexNibble( char ch )
{
  if( ch >= 'A' && ch <= 'F' )
    return (ch - 'A' + 0xa );
  else if( ch >= '0' && ch <= '9' )
    return ( ch - '0' );
  else if( ch >= 'a' && ch <= 'f' )
    return ( ch - 'a' + 0xa );
  else
  {
    printf( "should never get here\n" );
    return  -1;
  }
}
