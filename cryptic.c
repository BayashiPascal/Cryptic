// *************** CRYPTIC.C ***************

// ================= Include ==================
#include "cryptic.h"
#if BUILDMODE == 0
#include "cryptic-inline.c"
#endif

// ================ Functions implementation ==================

// Function to free the memory used by the static FeistelCiphering
void FeistelCipheringFreeStatic(
  FeistelCiphering* that) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Reset pointers
  that->keys = NULL;
  that->fun = NULL;

  // Free memory
  if (that->initVector != NULL) {

    free(that->initVector);
    that->initVector = NULL;

  }

  if (that->streamBuffer != NULL) {

    free(that->streamBuffer);
    that->streamBuffer = NULL;

  }

}

// Function to cipher the message 'msg' with the FeistelCiphering 'that'
// The message length 'lenMsg' must be a multiple of 2
// Return a new string containing the ciphered message
unsigned char* FeistelCipheringCipher(
  FeistelCiphering* that,
     unsigned char* msg,
      unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (msg == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'msg' is null");
    PBErrCatch(CrypticErr);

  }

  if ((lenMsg % 2) != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

#endif

  // Allocate memory for the ciphered message
  unsigned char* cipheredMsg =
    PBErrMalloc(
      CrypticErr,
      (lenMsg + 1));

  // Initialized the ciphered message with the initial message
  memcpy(
    cipheredMsg,
    msg,
    lenMsg + 1);

  // Declare a variable to memorize the half length of the message
  unsigned long halfLenMsg = lenMsg / 2;

  // Allocate memory for the ciphering function
  unsigned char* str =
    PBErrMalloc(
      CrypticErr,
      lenMsg);

  // Loop on keys
  GSetIterForward iter = GSetIterForwardCreateStatic(that->keys);
  do {

    // Get the key
    unsigned char* key = GSetIterGet(&iter);

    // Copy right half of the current ciphered message into the left
    // of the temporary string
    memcpy(
      str,
      cipheredMsg + halfLenMsg,
      halfLenMsg);

    // Cipher the right half and store it into the right of the
    // temporary string
    (that->fun)(
      cipheredMsg + halfLenMsg,
      str + halfLenMsg,
      key,
      halfLenMsg);

printf("A ");
for(unsigned int iChar=0;iChar<lenMsg;++iChar) printf("%d,",str[iChar]);
printf("\n");

    // Apply the XOR operator on the half right of the temporary
    // string with the left half of the ciphered message
    for (
      int iChar = halfLenMsg;
      iChar--;) {

      str[halfLenMsg + iChar] =
        str[halfLenMsg + iChar] ^
        cipheredMsg[iChar];

    }

printf("B ");
for(unsigned int iChar=0;iChar<lenMsg;++iChar) printf("%d,",str[iChar]);
printf("\n");

    // Copy the temporary string into the ciphered message
    memcpy(
      cipheredMsg,
      str,
      lenMsg);

  } while (GSetIterStep(&iter));

printf("C ");
for(unsigned int iChar=0;iChar<lenMsg;++iChar) printf("%d,",cipheredMsg[iChar]);
printf("\n");

  // Exchange the two halves of the ciphered message
  for (
    int iChar = halfLenMsg;
    iChar--;) {

    str[halfLenMsg + iChar] = cipheredMsg[iChar];
    str[iChar] = cipheredMsg[halfLenMsg + iChar];

  }

  memcpy(
    cipheredMsg,
    str,
    lenMsg);

printf("D ");
for(unsigned int iChar=0;iChar<lenMsg;++iChar) printf("%d,",cipheredMsg[iChar]);
printf("\n");

  // Free memory
  free(str);

  // Return the ciphered message
  return cipheredMsg;

}

// Function to decipher the message 'msg' with the FeistelCiphering
// 'that'
// The message length 'lenMsg' must be a multiple of 2
// Return a new string containing the deciphered message
unsigned char* FeistelCipheringDecipher(
  FeistelCiphering* that,
     unsigned char* msg,
      unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (msg == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'msg' is null");
    PBErrCatch(CrypticErr);

  }

  if ((lenMsg % 2) != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

#endif

  // Allocate memory for the ciphered message
  unsigned char* cipheredMsg =
    PBErrMalloc(
      CrypticErr,
      lenMsg + 1);

  // Initialized the ciphered message with the initial message
  memcpy(
    cipheredMsg,
    msg,
    lenMsg + 1);

  // Declare a variable to memorize the helf length of the message
  unsigned long halfLenMsg = lenMsg / 2;

  // Allocate memory for the ciphering function
  unsigned char* str =
    PBErrMalloc(
      CrypticErr,
      lenMsg);

  // Loop on keys
  GSetIterBackward iter = GSetIterBackwardCreateStatic(that->keys);
  do {

    // Get the key
    unsigned char* key = GSetIterGet(&iter);

    // Copy right half of the current ciphered message into the left
    // of the temporary string
    memcpy(
      str,
      cipheredMsg + halfLenMsg,
      halfLenMsg);

    // Cipher the right half and store it into the right of the
    // temporary string
    (that->fun)(
      cipheredMsg + halfLenMsg,
      str + halfLenMsg,
      key,
      halfLenMsg);

    // Apply the XOR operator on the half right of the temporary
    // string with the left half of the ciphered message
    for (
      int iChar = halfLenMsg;
      iChar--;) {

      str[halfLenMsg + iChar] =
        str[halfLenMsg + iChar] ^
        cipheredMsg[iChar];

    }

    // Copy the temporary string into the ciphered message
    memcpy(
      cipheredMsg,
      str,
      lenMsg);

  } while (GSetIterStep(&iter));

  // Exchange the two halves of the ciphered message
  for (
    int iChar = halfLenMsg;
    iChar--;) {

    str[halfLenMsg + iChar] = cipheredMsg[iChar];
    str[iChar] = cipheredMsg[halfLenMsg + iChar];

  }

  memcpy(
    cipheredMsg,
    str,
    lenMsg);

  // Free memory
  free(str);

  // Return the ciphered message
  return cipheredMsg;

}

// Function to cipher a stream of messages 'msg' with the
// FeistelCiphering 'that'
// The messages length 'lenMsg' must be a multiple of 2
// The messages of the 'streamIn' are consumed one after the other
// and the resulting ciphered messages is appended in the same order
// to 'streamOut'
// Memory used by the messages from the 'streamIn' is freed
// 'lenMsg' must be at least sizeof(that->counter) + 1
void FeistelCipheringCipherStream(
    FeistelCiphering* that,
       GSetStr* const streamIn,
       GSetStr* const streamOut,
  const unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (streamIn == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'streamIn' is null");
    PBErrCatch(CrypticErr);

  }

  if (streamOut == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'streamOut' is null");
    PBErrCatch(CrypticErr);

  }

  if ((lenMsg % 2) != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

  if (lenMsg <= sizeof(that->counter)) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is too small (%lu > %lu)",
      lenMsg,
      sizeof(that->counter));
    PBErrCatch(CrypticErr);

  }

#endif

  // Loop on the messages from the streamIn
  while (GSetNbElem(streamIn) > 0) {

    // Get the message
    unsigned char* msg = (unsigned char*)GSetPop(streamIn);

    // Declare some working variables
    unsigned char* cipheredMsg = NULL;
    unsigned char* xorArg = NULL;

    // Switch according to the operating mode
    switch (FeistelCipheringGetOpMode(that)) {

      case FeistelCipheringOpMode_ECB:

        // Cipher the message
        cipheredMsg =
          FeistelCipheringCipher(
            that,
            msg,
            lenMsg);

        // Append the ciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)cipheredMsg);

        break;

      case FeistelCipheringOpMode_CBC:

        // If there has been a previously ciphered message
        if (that->streamBuffer != NULL) {

          // The argument is the previously ciphered message
          xorArg = that->streamBuffer;

        // Else, this is the first ciphered message
        } else {

          // The argument is the initialisation vector
          xorArg = that->initVector;

        }

        // XOR the current message
        for (
          unsigned long iChar = 0;
          iChar < lenMsg;
          ++iChar) {

          msg[iChar] = msg[iChar] ^ xorArg[iChar];

        }

        // Cipher the message
        cipheredMsg =
          FeistelCipheringCipher(
            that,
            msg,
            lenMsg);

        // Append the ciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)cipheredMsg);

        // Free memory
        if (that->streamBuffer != NULL) {

          free(that->streamBuffer);

        }

        // Update the buffer with the last ciphered message
        that->streamBuffer = (unsigned char*)strdup((char*)cipheredMsg);

        break;

      case FeistelCipheringOpMode_CTR:

        // Update the counter in the initialization vector
        memcpy(
          that->initVector + lenMsg - sizeof(that->counter),
          (char*)(&(that->counter)),
          sizeof(that->counter));

        // Cipher the initialisation vector
        cipheredMsg =
          FeistelCipheringCipher(
            that,
            that->initVector,
            lenMsg);

        // XOR the current message with the ciphered initialisation
        // vector
        for (
          unsigned long iChar = 0;
          iChar < lenMsg;
          ++iChar) {

          cipheredMsg[iChar] =
            cipheredMsg[iChar] ^ msg[iChar];

        }

        // Append the ciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)cipheredMsg);

        // Increment the counter
        ++(that->counter);

        break;

      default:
        break;

    }

    // Free the message
    free(msg);

  }

}

// Function to decipher a stream of messages 'msg' with the
// FeistelCiphering 'that'
// The messages length 'lenMsg' must be a multiple of 2
// The messages of the 'streamIn' are consumed one after the other
// and the resulting deciphered messages is appended in the same order
// to 'streamOut'
// Memory used by the messages from the 'streamIn' is freed
// 'lenMsg' must be at least sizeof(that->counter) + 1
void FeistelCipheringDecipherStream(
    FeistelCiphering* that,
       GSetStr* const streamIn,
       GSetStr* const streamOut,
  const unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (streamIn == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'streamIn' is null");
    PBErrCatch(CrypticErr);

  }

  if (streamOut == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'streamOut' is null");
    PBErrCatch(CrypticErr);

  }

  if ((lenMsg % 2) != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

  if (lenMsg <= sizeof(that->counter)) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is too small (%lu > %lu)",
      lenMsg,
      sizeof(that->counter));
    PBErrCatch(CrypticErr);

  }

#endif

  // Loop on the messages from the streamIn
  while (GSetNbElem(streamIn) > 0) {

    // Get the message
    unsigned char* msg = (unsigned char*)GSetPop(streamIn);

    // Declare some working variables
    unsigned char* decipheredMsg = NULL;
    unsigned char* xorArg = NULL;

    // Switch according to the operating mode
    switch (FeistelCipheringGetOpMode(that)) {

      case FeistelCipheringOpMode_ECB:

        // Decipher the message
        decipheredMsg =
          FeistelCipheringDecipher(
            that,
            msg,
            lenMsg);

        // Append the deciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)decipheredMsg);

        break;

      case FeistelCipheringOpMode_CBC:

        // Decipher the message
        decipheredMsg =
          FeistelCipheringDecipher(
            that,
            msg,
            lenMsg);

          // If there has been a previously ciphered message
          if (that->streamBuffer != NULL) {

            // The argument is the previously ciphered message
            xorArg = that->streamBuffer;

          // Else, this is the first ciphered message
          } else {

            // The argument is the initialisation vector
            xorArg = that->initVector;

          }

          // XOR the current message
          for (
            unsigned long iChar = 0;
            iChar < lenMsg;
            ++iChar) {

            decipheredMsg[iChar] =
              decipheredMsg[iChar] ^ xorArg[iChar];

          }

        // Append the deciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)decipheredMsg);

        // Free memory
        if (that->streamBuffer != NULL) {

          free(that->streamBuffer);

        }

        // Update the buffer with the last deciphered message
        that->streamBuffer = (unsigned char*)strdup((char*)msg);

        break;

      case FeistelCipheringOpMode_CTR:

        // Update the counter in the initialization vector
        memcpy(
          that->initVector + lenMsg - sizeof(that->counter),
          (char*)(&(that->counter)),
          sizeof(that->counter));

        // Cipher the initialisation vector
        decipheredMsg =
          FeistelCipheringCipher(
            that,
            that->initVector,
            lenMsg);

        // XOR the current message with the ciphered initialisation
        // vector
        for (
          unsigned long iChar = 0;
          iChar < lenMsg;
          ++iChar) {

          decipheredMsg[iChar] =
            decipheredMsg[iChar] ^ msg[iChar];

        }

        // Append the ciphered message to the streamOut
        GSetAppend(
          streamOut,
          (char*)decipheredMsg);

        // Increment the counter
        ++(that->counter);

        break;

      default:
        break;

    }

    // Free the message
    free(msg);

  }

}

// Function to cipher a file 'fpIn' with the FeistelCiphering 'that'
// Save the result in the file 'fpOut'.
// Uses block of size equals to the key size for ECB or computed from
// the initialization vector for CBC and CTR.
// Keys must have been set and the stream initialised prior
// to calling this function
void FeistelCipheringCipherFile(
  FeistelCiphering* that,
        FILE* const fpIn,
        FILE* const fpOut) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (fpIn == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'fpIn' is null");
    PBErrCatch(CrypticErr);

  }

  if (fpOut == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'fpOut' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Get the size of blocks
  unsigned long sizeBlock = FeistelCipheringGetDefaultSizeBlock(that);

  // Create the stream of blocks
  GSetStr streamIn = GSetStrCreateStatic();

  // Load the file in the set of blocks
  while (!feof(fpIn)) {

    // Allocate memory to read the block
    unsigned char* block =
      PBErrMalloc(
        CrypticErr,
        sizeBlock);

    // Read the block
    unsigned long nbRead =
      fread(
        block,
        1,
        sizeBlock,
        fpIn);

    // If we could read the block (i.e. not an empty line at the end of
    // a text file)
    if (nbRead != 0) {

      // If the block is incomplete
      if (nbRead != sizeBlock) {

        // Pad with null character
        memset(
          block + nbRead,
          ' ',
          sizeBlock - nbRead);

      }

printf("block ");
for(unsigned int iChar=0;iChar<sizeBlock;++iChar) printf("%d,",block[iChar]);
printf("\n");

      // Add the block to the stream
      GSetAppend(
        &streamIn,
        (char*)block);

    }

  }

  // Create the stream of ciphered blocks
  GSetStr streamOut = GSetStrCreateStatic();

  // Cipher the stream
  FeistelCipheringCipherStream(
    that,
    &streamIn,
    &streamOut,
    sizeBlock);

  // Save the ciphered stream to the output file
  while (GSetNbElem(&streamOut) > 0) {

    // Get the block
    unsigned char* block = (unsigned char*)GSetPop(&streamOut);

    // Save it to the output file
    unsigned long nbWrite =
      fwrite(
        block,
        1,
        sizeBlock,
        fpOut);
    (void)nbWrite;

    // Free memory
    free(block);

  }

}

// Function to decipher a file 'fpIn' with the FeistelCiphering 'that'
// Save the result in the file 'fpOut'.
// Uses block of size equals to the key size for ECB or computed from
// the initialization vector for CBC and CTR.
// Keys must have been set and the stream initialised prior
// to calling this function
void FeistelCipheringDecipherFile(
  FeistelCiphering* that,
        FILE* const fpIn,
        FILE* const fpOut) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

  if (fpIn == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'fpIn' is null");
    PBErrCatch(CrypticErr);

  }

  if (fpOut == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'fpOut' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Get the size of blocks
  unsigned long sizeBlock = FeistelCipheringGetDefaultSizeBlock(that);

  // Create the stream of blocks
  GSetStr streamIn = GSetStrCreateStatic();

  // Load the file in the set of blocks
  while (!feof(fpIn)) {

    // Allocate memory to read the block
    unsigned char* block =
      PBErrMalloc(
        CrypticErr,
        sizeBlock);

    // Read the block
    unsigned long nbRead =
      fread(
        block,
        1,
        sizeBlock,
        fpIn);

    // If we could read the block (i.e. not an empty line at the end of
    // a text file)
    if (nbRead != 0) {

      // If the block is incomplete
      if (nbRead != sizeBlock) {

        // Pad with null character
        memset(
          block + nbRead,
          ' ',
          sizeBlock - nbRead);

      }

      
      if (nbRead != 0) {

        // Add the block to the stream
        GSetAppend(
          &streamIn,
          (char*)block);

      }

    }

  }

  // Create the stream of ciphered blocks
  GSetStr streamOut = GSetStrCreateStatic();

  // Decipher the stream
  FeistelCipheringDecipherStream(
    that,
    &streamIn,
    &streamOut,
    sizeBlock);

  // Save the ciphered stream to the output file
  while (GSetNbElem(&streamOut) > 0) {

    // Get the block
    unsigned char* block = (unsigned char*)GSetPop(&streamOut);

    // Save it to the output file
    unsigned long nbWrite =
      fwrite(
        block,
        1,
        sizeBlock,
        fpOut);
    (void)nbWrite;

    // Free memory
    free(block);

  }

}

