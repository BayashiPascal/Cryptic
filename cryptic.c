// *************** CRYPTIC.C ***************

// ================= Include ==================
#include "cryptic.h"
#if BUILDMODE == 0
#include "cryptic-inline.c"
#endif

// ================ Functions implementation ==================

// Function to free the memory used by the static FeistelCyphering
void FeistelCypheringFreeStatic(
  FeistelCyphering* that) {

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

}

// Function to cypher the message 'msg' with the FeistelCyphering 'that'
// The message length 'lenMsg' must be a multiple of the length of
// the keys
// Return a new string containing the cyphered message
unsigned char* FeistelCypheringCypher(
  FeistelCyphering* that,
  unsigned char* msg,
  unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'keys' is null");
    PBErrCatch(CrypticErr);

  }

  if (msg == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'msg' is null");
    PBErrCatch(CrypticErr);

  }

  if (lenMsg % 2 != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

#endif

  // Allocate memory for the cyphered message
  unsigned char* cypheredMsg =
    PBErrMalloc(
      CrypticErr,
      lenMsg * sizeof(unsigned char));

  // Initialized the cyphered message with the initial message
  memcpy(
    cypheredMsg,
    msg,
    lenMsg);

  // Declare a variable to memorize the helf length of the message
  unsigned long halfLenMsg = lenMsg / 2;

  // Allocate memory for the cyphering function
  unsigned char* str =
    PBErrMalloc(
      CrypticErr,
      halfLenMsg * sizeof(unsigned char));

  // Loop on keys
  GSetIterForward iter = GSetIterForwardCreateStatic(that->keys);
  do {

    // Get the key
    unsigned char* key = GSetIterGet(&iter);

    // Copy right half of the current cyphered message into the left
    // of the temporary string
    memcpy(
      str,
      cypheredMsg + halfLenMsg,
      halfLenMsg);

    // Cypher the right half and store it into the right of the
    // temporary string
    (that->fun)(
      cypheredMsg + halfLenMsg,
      str + halfLenMsg,
      key,
      halfLenMsg);

    // Apply the XOR operator on the half right of the temporary
    // string with the left half of the cyphered message
    for (
      int iChar = halfLenMsg;
      iChar--;) {

      str[halfLenMsg + iChar] =
        str[halfLenMsg + iChar] ^
        cypheredMsg[iChar];

    }

    // Copy the temporary string into the cyphered message
    memcpy(
      cypheredMsg,
      str,
      lenMsg);

  } while (GSetIterStep(&iter));

  // Exchange the two halves of the cyphered message
  for (
    int iChar = halfLenMsg;
    iChar--;) {

    str[halfLenMsg + iChar] = cypheredMsg[iChar];
    str[iChar] = cypheredMsg[halfLenMsg + iChar];

  }

  memcpy(
    cypheredMsg,
    str,
    lenMsg);

  // Free memory
  free(str);

  // Return the cyphered message
  return cypheredMsg;

}

// Function to decypher the message 'msg' with the FeistelCyphering
// 'that'
// The message length 'lenMsg' must be a multiple of the length of
// the keys
// Return a new string containing the decyphered message
unsigned char* FeistelCypheringDecypher(
  FeistelCyphering* that,
  unsigned char* msg,
  unsigned long lenMsg) {

#if BUILDMODE == 0

  if (that == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'keys' is null");
    PBErrCatch(CrypticErr);

  }

  if (msg == NULL) {

    CrypticErr->_type = PBErrTypeNullPointer;
    sprintf(
      CrypticErr->_msg,
      "'msg' is null");
    PBErrCatch(CrypticErr);

  }

  if (lenMsg % 2 != 0) {

    CrypticErr->_type = PBErrTypeInvalidArg;
    sprintf(
      CrypticErr->_msg,
      "'lenMsg' is not multiple of 2 (%lu)",
      lenMsg);
    PBErrCatch(CrypticErr);

  }

#endif

  // Allocate memory for the cyphered message
  unsigned char* cypheredMsg =
    PBErrMalloc(
      CrypticErr,
      lenMsg * sizeof(unsigned char));

  // Initialized the cyphered message with the initial message
  memcpy(
    cypheredMsg,
    msg,
    lenMsg);

  // Declare a variable to memorize the helf length of the message
  unsigned long halfLenMsg = lenMsg / 2;

  // Allocate memory for the cyphering function
  unsigned char* str =
    PBErrMalloc(
      CrypticErr,
      halfLenMsg * sizeof(unsigned char));

  // Loop on keys
  GSetIterBackward iter = GSetIterBackwardCreateStatic(that->keys);
  do {

    // Get the key
    unsigned char* key = GSetIterGet(&iter);

    // Copy right half of the current cyphered message into the left
    // of the temporary string
    memcpy(
      str,
      cypheredMsg + halfLenMsg,
      halfLenMsg);

    // Cypher the right half and store it into the right of the
    // temporary string
    (that->fun)(
      cypheredMsg + halfLenMsg,
      str + halfLenMsg,
      key,
      halfLenMsg);

    // Apply the XOR operator on the half right of the temporary
    // string with the left half of the cyphered message
    for (
      int iChar = halfLenMsg;
      iChar--;) {

      str[halfLenMsg + iChar] =
        str[halfLenMsg + iChar] ^
        cypheredMsg[iChar];

    }

    // Copy the temporary string into the cyphered message
    memcpy(
      cypheredMsg,
      str,
      lenMsg);

  } while (GSetIterStep(&iter));

  // Exchange the two halves of the cyphered message
  for (
    int iChar = halfLenMsg;
    iChar--;) {

    str[halfLenMsg + iChar] = cypheredMsg[iChar];
    str[iChar] = cypheredMsg[halfLenMsg + iChar];

  }

  memcpy(
    cypheredMsg,
    str,
    lenMsg);

  // Free memory
  free(str);

  // Return the cyphered message
  return cypheredMsg;

}
