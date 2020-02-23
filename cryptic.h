// *************** CRYPTIC.H ***************
#ifndef CRYPTIC_H
#define CRYPTIC_H

// ================= Include ==================
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "pberr.h"
#include "gset.h"

// ================= Define ==================

// ================= Data structures ===================

// Structure for the Feistel cypher
typedef struct FeistelCyphering {

  // GSet of null terminated strings, all the same size,
  // which are the keys to cypher/decypher
  GSetStr* keys;

  // Function to be used during cyphering
  void (*fun)(
    unsigned char*,
    unsigned char*,
    unsigned char*,
    unsigned long);

} FeistelCyphering;

// ================ Functions declaration ====================

// Static constructor for a Feistel cypher,
// 'keys' is a GSet of null terminated strings, all the same size
// 'fun' is the cyphering function of the form
// void (*fun)(char* src, char* dest, char* key, unsigned long len)
// 'src', 'dest' have same length 'len'
// 'key' may be of any length
#if BUILDMODE != 0
static inline
#endif
FeistelCyphering FeistelCypheringCreateStatic(
  GSetStr* keys,
  void (*fun)(
    unsigned char*,
    unsigned char*,
    unsigned char*,
    unsigned long));

// Function to free the memory used by the static FeistelCyphering
void FeistelCypheringFreeStatic(
  FeistelCyphering* that);

// Function to cypher the message 'msg' with the FeistelCyphering 'that'
// The message length 'lenMsg' must be a multiple of the length of
// the keys
// Return a new string containing the cyphered message
unsigned char* FeistelCypheringCypher(
  FeistelCyphering* that,
  unsigned char* msg,
  unsigned long lenMsg);

// Function to decypher the message 'msg' with the FeistelCyphering
// 'that'
// The message length 'lenMsg' must be a multiple of the length of
// the keys
// Return a new string containing the decyphered message
unsigned char* FeistelCypheringDecypher(
  FeistelCyphering* that,
  unsigned char* msg,
  unsigned long lenMsg);

// ================ inliner ====================

#if BUILDMODE != 0
#include "cryptic-inline.c"
#endif

#endif
