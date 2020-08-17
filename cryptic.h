// *************** CRYPTIC.H ***************
#ifndef CRYPTIC_H
#define CRYPTIC_H

// ================= Include ==================
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include "pberr.h"
#include "gset.h"

// ================= Define ==================

#define FUN_CIPHER \
  (*fun)( \
    unsigned char*, \
    unsigned char*, \
    unsigned char*, \
    uint32_t)

#define CRYPTIC_DEFAULT_OP_MODE FeistelCipheringOpMode_CTR

// ================= Data structures ===================

// Operating mode
typedef enum FeistelCipheringOpMode {

  FeistelCipheringOpMode_ECB,
  FeistelCipheringOpMode_CBC,
  FeistelCipheringOpMode_CTR

} FeistelCipheringOpMode;

// Structure for the Feistel cipher
typedef struct FeistelCiphering {

  // GSet of null terminated strings, all the same size,
  // which are the keys to cipher/decipher
  GSetStr* keys;

  // Function to be used during ciphering
  void FUN_CIPHER;

  // Operating mode
  FeistelCipheringOpMode mode;

  // Initialization vector as a null terminated string
  // Used by CBC and CTR operating mode
  // In case of CTR, space for the counter is allocated at the end of
  // the initVector given by the user to append the counter
  unsigned char* initVector;

  // Buffer for the encoding/decoding when using CBC and CTR
  unsigned char* streamBuffer;

  // Counter for the CTR operating mode
  uint32_t counter;

} FeistelCiphering;

// ================ Functions declaration ====================

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
      void FUN_CIPHER);

// Function to free the memory used by the static FeistelCiphering
void FeistelCipheringFreeStatic(
  FeistelCiphering* that);

// Function to cipher the message 'msg' with the FeistelCiphering 'that'
// The message length 'lenMsg' must be a multiple of 2
// Return a new string containing the ciphered message
unsigned char* FeistelCipheringCipher(
  FeistelCiphering* that,
     unsigned char* msg,
           uint32_t lenMsg);

// Function to decipher the message 'msg' with the FeistelCiphering
// 'that'
// The message length 'lenMsg' must be a multiple of 2
// Return a new string containing the deciphered message
unsigned char* FeistelCipheringDecipher(
  FeistelCiphering* that,
     unsigned char* msg,
           uint32_t lenMsg);

// Get the operating mode of the FeistelCiphering 'that'
#if BUILDMODE != 0
static inline
#endif
FeistelCipheringOpMode FeistelCipheringGetOpMode(
  const FeistelCiphering* const that);

// Set the operating mode of the FeistelCiphering 'that' to 'mode'
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringSetOpMode(
  FeistelCiphering* const that,
   FeistelCipheringOpMode mode);

// Get the initialisation vector of the FeistelCiphering 'that'
#if BUILDMODE != 0
static inline
#endif
const unsigned char* FeistelCipheringGetInitVec(
  const FeistelCiphering* const that);

// Set the initialisation vector of the FeistelCiphering 'that'
// to 'initVec'
// Allocate extra memory to append the counter at the end of the
// initialisation vector if the operation mode is CTR
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringSetInitVec(
     FeistelCiphering* const that,
  const unsigned char* const initVec);

// Initialise the stream encoding/decoding of the FeistelCiphering 'that'
// with the initialization vector 'initVec'
#if BUILDMODE != 0
static inline
#endif
void FeistelCipheringInitStream(
     FeistelCiphering* const that,
  const unsigned char* const initVec);

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
     const uint32_t lenMsg);

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
     const uint32_t lenMsg);

// Get the required size of the initialisation vector for the
// FeistelCiphering 'that' for messages of length 'lenMsg'
#if BUILDMODE != 0
static inline
#endif
uint32_t FeistelCipheringGetReqSizeInitVec(
  const FeistelCiphering* const that,
                 const uint32_t lenMsg);

// Function to cipher a file 'fpIn' with the FeistelCiphering 'that'
// Save the result in the file 'fpOut'.
// Uses block of size equals to the key size for ECB or computed from
// the initialization vector for CBC and CTR.
// Keys must have been set and the stream initialised prior
// to calling this function
void FeistelCipheringCipherFile(
  FeistelCiphering* that,
        FILE* const fpIn,
        FILE* const fpOut);

// Function to decipher a file 'fpIn' with the FeistelCiphering 'that'
// Save the result in the file 'fpOut'.
// Uses block of size equals to the key size for ECB or computed from
// the initialization vector for CBC and CTR.
// Keys must have been set and the stream initialised prior
// to calling this function
void FeistelCipheringDecipherFile(
  FeistelCiphering* that,
        FILE* const fpIn,
        FILE* const fpOut);

// Get the default size of blocks for the FeistelCiphering 'that'
// It's the key size for ECB or computed from
// the initialization vector for CBC and CTR.
#if BUILDMODE != 0
static inline
#endif
uint32_t FeistelCipheringGetDefaultSizeBlock(
  const FeistelCiphering* const that);

// ================ inliner ====================

#if BUILDMODE != 0
#include "cryptic-inline.c"
#endif

#endif
