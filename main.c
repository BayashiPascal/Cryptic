#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cryptic.h"

void CipheringFun(
  unsigned char* src,
  unsigned char* dest,
  unsigned char* key,
   unsigned long len) {

  unsigned long lenKey = strlen((char*)key);
  for (
    unsigned int iChar = 0;
    iChar < len;
    ++iChar) {

    dest[iChar] = src[iChar] + key[iChar % lenKey];

  }

}

void UnitTestFeistelCiphering() {

  GSetStr keys = GSetStrCreateStatic();
  unsigned char keyA[] = "123456";
  unsigned char keyB[] = "abcdef";
  GSetAppend(
    &keys,
    (char*)keyA);
  GSetAppend(
    &keys,
    (char*)keyB);
  unsigned char msg[] = "Hello World.";
  printf("Message:          ");
  for (
    unsigned int iChar = 0;
    iChar < strlen((char*)msg);
    ++iChar) {

    printf(
      "%03u,",
      msg[iChar]);

  }

  printf("\n");
  FeistelCiphering cipher =
    FeistelCipheringCreateStatic(
      &keys,
      &CipheringFun);
  unsigned char* cipheredMsg =
    FeistelCipheringCipher(
      &cipher,
      msg,
      strlen((char*)msg));
  printf("Ciphered message: ");
  for (
    unsigned int iChar = 0;
    iChar < strlen((char*)msg);
    ++iChar) {

    printf(
      "%03u,",
      cipheredMsg[iChar]);

  }

  printf("\n");
  unsigned char* decipheredMsg =
    FeistelCipheringDecipher(
      &cipher,
      cipheredMsg,
      strlen((char*)msg));
  int ret =
    strcmp(
      (char*)msg,
      (char*)decipheredMsg);
  if (ret != 0) {

    CrypticErr->_type = PBErrTypeUnitTestFailed;
    sprintf(
      CrypticErr->_msg,
      "FeistelCipheringCipher/FeistelCipheringDecipher NOK");
    PBErrCatch(CrypticErr);

  }

  printf(
    "%s\n",
    decipheredMsg);

  FeistelCipheringFreeStatic(&cipher);
  GSetFlush(&keys);
  free(cipheredMsg);
  free(decipheredMsg);
  printf("UnitTestFeistelCiphering OK\n");

}

void UnitTestFeistelStreamCipheringECB() {

  GSetStr keys = GSetStrCreateStatic();
  unsigned char keyA[] = "123456";
  unsigned char keyB[] = "abcdef";
  GSetAppend(
    &keys,
    (char*)keyA);
  GSetAppend(
    &keys,
    (char*)keyB);
  unsigned char* initVector = (unsigned char*)"!`#$%&'()~=.";
  GSetStr streamIn = GSetStrCreateStatic();
  unsigned char* msg[2] = {

      (unsigned char*)"Hello World.    ",
      (unsigned char*)"What's up there?"

    };
  unsigned long lenMsg = strlen((char*)(msg[0]));
  for (int iMsg = 0; iMsg < 2; ++iMsg) {

    GSetAppend(
      &streamIn,
      strdup((char*)(msg[iMsg])));
    printf("Message:            ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        msg[iMsg][iChar]);

    }

    printf("\n");

  }

  FeistelCiphering cipher =
    FeistelCipheringCreateStatic(
      &keys,
      &CipheringFun);
  GSetStr streamOut = GSetStrCreateStatic();
  GSetStr streamDecipher = GSetStrCreateStatic();
  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringSetInitVec(
    &cipher,
    initVector);
  FeistelCipheringCipherStream(
    &cipher,
    &streamIn,
    &streamOut,
    lenMsg);
  while (GSetNbElem(&streamOut) > 0) {

    unsigned char* cipheredMsg = (unsigned char*)GSetPop(&streamOut);
    printf("Ciphered message:   ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        cipheredMsg[iChar]);

    }

    printf("\n");
    GSetAppend(
      &streamDecipher,
      (char*)cipheredMsg);

  }

  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringDecipherStream(
    &cipher,
    &streamDecipher,
    &streamIn,
    lenMsg);

  int iMsg = 0;
  while (GSetNbElem(&streamIn) > 0) {

    unsigned char* decipheredMsg = (unsigned char*)GSetPop(&streamIn);
    printf("Deciphered message: ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        decipheredMsg[iChar]);

    }

    printf("\n");
    printf(
      "%s\n",
      (char*)decipheredMsg);

    int ret =
      strcmp(
        (char*)(msg[iMsg]),
        (char*)decipheredMsg);
    if (ret != 0) {

      CrypticErr->_type = PBErrTypeUnitTestFailed;
      sprintf(
        CrypticErr->_msg,
        "FeistelCipheringCipherECB/FeistelCipheringDecipherECB NOK");
      PBErrCatch(CrypticErr);

    }
    ++iMsg;

    free(decipheredMsg);

  }

  FeistelCipheringFreeStatic(&cipher);
  GSetFlush(&keys);
  printf("UnitTestFeistelStreamCipheringECB OK\n");

}

void UnitTestFeistelStreamCipheringCBC() {

  GSetStr keys = GSetStrCreateStatic();
  unsigned char keyA[] = "123456";
  unsigned char keyB[] = "abcdef";
  GSetAppend(
    &keys,
    (char*)keyA);
  GSetAppend(
    &keys,
    (char*)keyB);
  unsigned char* initVector = (unsigned char*)"!`#$%&'()~=.1234";
  GSetStr streamIn = GSetStrCreateStatic();
  unsigned char* msg[2] = {

      (unsigned char*)"Hello World.    ",
      (unsigned char*)"What's up there?"

    };
  unsigned long lenMsg = strlen((char*)(msg[0]));
  for (int iMsg = 0; iMsg < 2; ++iMsg) {

    GSetAppend(
      &streamIn,
      strdup((char*)(msg[iMsg])));
    printf("Message:            ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        msg[iMsg][iChar]);

    }

    printf("\n");

  }

  FeistelCiphering cipher =
    FeistelCipheringCreateStatic(
      &keys,
      &CipheringFun);
  FeistelCipheringSetOpMode(
    &cipher,
    FeistelCipheringOpMode_CBC);
  unsigned long reqSize =
    FeistelCipheringGetReqSizeInitVec(
      &cipher,
      lenMsg);
  printf(
    "Required initialisation vector's size: %lu\n",
    reqSize);
  FeistelCipheringSetInitVec(
    &cipher,
    initVector);
  GSetStr streamOut = GSetStrCreateStatic();
  GSetStr streamDecipher = GSetStrCreateStatic();
  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringCipherStream(
    &cipher,
    &streamIn,
    &streamOut,
    lenMsg);
  while (GSetNbElem(&streamOut) > 0) {

    unsigned char* cipheredMsg = (unsigned char*)GSetPop(&streamOut);
    printf("Ciphered message:   ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        cipheredMsg[iChar]);

    }

    printf("\n");
    GSetAppend(
      &streamDecipher,
      (char*)cipheredMsg);

  }

  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringDecipherStream(
    &cipher,
    &streamDecipher,
    &streamIn,
    lenMsg);

  unsigned int iMsg = 0;
  while (GSetNbElem(&streamIn) > 0) {

    unsigned char* decipheredMsg = (unsigned char*)GSetPop(&streamIn);
    printf("Deciphered message: ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        decipheredMsg[iChar]);

    }

    printf("\n");
    printf(
      "%s\n",
      (char*)decipheredMsg);

    int ret =
      strcmp(
        (char*)(msg[iMsg]),
        (char*)decipheredMsg);
    if (ret != 0) {

      CrypticErr->_type = PBErrTypeUnitTestFailed;
      sprintf(
        CrypticErr->_msg,
        "FeistelCipheringCipherCBC/FeistelCipheringDecipherCBC NOK");
      PBErrCatch(CrypticErr);

    }
    ++iMsg;

    free(decipheredMsg);

  }

  FeistelCipheringFreeStatic(&cipher);
  GSetFlush(&keys);
  printf("UnitTestFeistelStreamCipheringCBC OK\n");

}

void UnitTestFeistelStreamCipheringCTR() {

  GSetStr keys = GSetStrCreateStatic();
  unsigned char keyA[] = "123456";
  unsigned char keyB[] = "abcdef";
  GSetAppend(
    &keys,
    (char*)keyA);
  GSetAppend(
    &keys,
    (char*)keyB);
  unsigned char* initVector = (unsigned char*)"!`#$%&'(";
  GSetStr streamIn = GSetStrCreateStatic();
  unsigned char* msg[2] = {

      (unsigned char*)"Hello World.    ",
      (unsigned char*)"What's up there?"

    };
  unsigned long lenMsg = strlen((char*)(msg[0]));
  for (int iMsg = 0; iMsg < 2; ++iMsg) {

    GSetAppend(
      &streamIn,
      strdup((char*)(msg[iMsg])));
    printf("Message:            ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        msg[iMsg][iChar]);

    }

    printf("\n");

  }

  FeistelCiphering cipher =
    FeistelCipheringCreateStatic(
      &keys,
      &CipheringFun);
  FeistelCipheringSetOpMode(
    &cipher,
    FeistelCipheringOpMode_CTR);
  unsigned long reqSize =
    FeistelCipheringGetReqSizeInitVec(
      &cipher,
      lenMsg);
  printf(
    "Required initialisation vector's size: %lu\n",
    reqSize);
  FeistelCipheringSetInitVec(
    &cipher,
    initVector);
  GSetStr streamOut = GSetStrCreateStatic();
  GSetStr streamDecipher = GSetStrCreateStatic();
  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringCipherStream(
    &cipher,
    &streamIn,
    &streamOut,
    lenMsg);
  while (GSetNbElem(&streamOut) > 0) {

    unsigned char* cipheredMsg = (unsigned char*)GSetPop(&streamOut);
    printf("Ciphered message:   ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        cipheredMsg[iChar]);

    }

    printf("\n");
    GSetAppend(
      &streamDecipher,
      (char*)cipheredMsg);

  }

  FeistelCipheringInitStream(
    &cipher,
    initVector);
  FeistelCipheringDecipherStream(
    &cipher,
    &streamDecipher,
    &streamIn,
    lenMsg);

  unsigned int iMsg = 0;
  while (GSetNbElem(&streamIn) > 0) {

    unsigned char* decipheredMsg = (unsigned char*)GSetPop(&streamIn);
    printf("Deciphered message: ");
    for (
      unsigned int iChar = 0;
      iChar < lenMsg;
      ++iChar) {

      printf(
        "%03u,",
        decipheredMsg[iChar]);

    }

    printf("\n");
    printf(
      "%s\n",
      (char*)decipheredMsg);

    int ret =
      strcmp(
        (char*)(msg[iMsg]),
        (char*)decipheredMsg);
    if (ret != 0) {

      CrypticErr->_type = PBErrTypeUnitTestFailed;
      sprintf(
        CrypticErr->_msg,
        "FeistelCipheringCipherCTR/FeistelCipheringDecipherCTR NOK");
      PBErrCatch(CrypticErr);

    }
    ++iMsg;

    free(decipheredMsg);

  }

  FeistelCipheringFreeStatic(&cipher);
  GSetFlush(&keys);
  printf("UnitTestFeistelStreamCipheringCTR OK\n");

}

void UnitTestAll() {

  UnitTestFeistelCiphering();
  UnitTestFeistelStreamCipheringECB();
  UnitTestFeistelStreamCipheringCBC();
  UnitTestFeistelStreamCipheringCTR();
  printf("UnitTestAll OK\n");

}

int main() {

  UnitTestAll();

  // Return success code
  return 0;

}
