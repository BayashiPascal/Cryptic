// *************** CRYPTIC-INLINE.C ***************

// ================ Functions implementation ====================

// Static constructor for a Feistel cipher,
// 'keys' is a GSet of null terminated strings, all the same size
// 'fun' is the ciphering function of the form
// void (*fun)(char* src, char* dest, char* key, uint32_t len)
// 'src', 'dest' have same length 'len'
// 'key' may be of any length
#if BUILDMODE != 0
static inline
#endif
FeistelCiphering FeistelCipheringCreateStatic(
  GSetStr* keys,
      void FUN_CIPHER) {

#if BUILDMODE == 0

  if (keys == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'keys' is null");
    PBErrCatch(CrypticErr);

  }

  if (fun == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'fun' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Declare a FeistelCiphering and set the properties
  FeistelCiphering c = {

    .keys = keys,
    .fun = fun,
    .mode = CRYPTIC_DEFAULT_OP_MODE,
    .initVector = NULL,
    .streamBuffer = NULL,
    .counter = 0

  };

  // Return the FeistelCiphering
  return c;

}

// Get the operating mode of the FeistelCiphering 'that'
#if BUILDMODE != 0
static inline
#endif
FeistelCipheringOpMode FeistelCipheringGetOpMode(
  const FeistelCiphering* const that) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Return the operating mode
  return that->mode;

}

// Set the operating mode of the FeistelCiphering 'that' to 'mode'
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringSetOpMode(
  FeistelCiphering* const that,
   FeistelCipheringOpMode mode) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Set the operating mode
  that->mode = mode;

}

// Get the initialisation vector of the FeistelCiphering 'that'
#if BUILDMODE != 0
static inline
#endif
const unsigned char* FeistelCipheringGetInitVec(
  const FeistelCiphering* const that) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Return the initialising vector
  return that->initVector;

}

// Set the initialisation vector of the FeistelCiphering 'that'
// to 'initVec'
// Allocate extra memory to append the counter at the end of the
// initialisation vector if the operation mode is CTR
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringSetInitVec(
     FeistelCiphering* const that,
  const unsigned char* const initVec) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Free memory if necessary
  if (that->initVector != NULL) {

    free(that->initVector);

  }

  switch (FeistelCipheringGetOpMode(that)) {

    case FeistelCipheringOpMode_CBC:

      // Copy the initialising vector
      that->initVector = (unsigned char*)strdup((char*)initVec);
      break;

    case FeistelCipheringOpMode_CTR:

      // Allocate memory
      that->initVector =
        (unsigned char*)malloc(
          strlen((char*)initVec) + 1 + sizeof(that->counter));

      // Init all the bytes to null
      memset(
        that->initVector,
        0,
        strlen((char*)initVec) + 1 + sizeof(that->counter));

      // Copy the initialising vector
      memcpy(
        that->initVector,
        initVec,
        strlen((char*)initVec));

      break;

    default:

      break;

    }

}

// Initialise the stream encoding/decoding of the FeistelCiphering 'that'
// with the initialization vector 'initVec'
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringInitStream(
     FeistelCiphering* const that,
  const unsigned char* const initVec) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Initialise the properties used to encode/decode the stream
  that->counter = 0;
  FeistelCipheringSetInitVec(
    that,
    initVec);
  if (that->streamBuffer != NULL) {

    free(that->streamBuffer);

  }

  that->streamBuffer = NULL;

}

// Get the required size of the initialisation vector for the
// FeistelCiphering 'that' for messages of length 'lenMsg'
#if BUILDMODE != 0
static inline
#endif
uint32_t FeistelCipheringGetReqSizeInitVec(
  const FeistelCiphering* const that,
                 const uint32_t lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Declare a variable to memorize the size
  uint32_t size = 0;

  // Return the size of initialising vector
  switch (FeistelCipheringGetOpMode(that)) {

    case FeistelCipheringOpMode_CBC:

      size = lenMsg;
      break;

    case FeistelCipheringOpMode_CTR:

      size = lenMsg - sizeof(that->counter);
      break;

    default:

      size = 0;

  }

  // Return the size of initialising vector
  return size;

}

// Get the default size of blocks for the FeistelCiphering 'that'
// It's the key size for ECB or computed from
// the initialization vector for CBC and CTR.
#if BUILDMODE != 0
static inline
#endif
uint32_t FeistelCipheringGetDefaultSizeBlock(
  const FeistelCiphering* const that) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'that' is null");
    PBErrCatch(CrypticErr);

  }

#endif

  // Calculate the size of blocks
  uint32_t sizeBlock = 0;
  unsigned char* key = NULL;
  switch (FeistelCipheringGetOpMode(that)) {

    case FeistelCipheringOpMode_ECB:
      key = (unsigned char*)
        GSetGet(
          that->keys,
          0);
      sizeBlock = strlen((char*)key);
      break;

    case FeistelCipheringOpMode_CBC:
      sizeBlock = strlen((char*)(that->initVector));
      break;

    case FeistelCipheringOpMode_CTR:
      sizeBlock =
        strlen((char*)(that->initVector)) + sizeof(that->counter);
      break;

    default:
      break;

  }

  // Return the size of block
  return sizeBlock;

}
