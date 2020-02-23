// *************** CRYPTIC-INLINE.C ***************

// ================ Functions implementation ====================

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
    unsigned long)) {

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

  // Declare a FeistelCyphering and set the properties
  FeistelCyphering c = {

    .keys = keys,
    .fun = fun

  };

  // Return the FeistelCyphering
  return c;

}
