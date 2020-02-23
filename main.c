#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cryptic.h"

void CypheringFun(
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

void UnitTestFeistelCyphering() {

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
  FeistelCyphering cypher =
    FeistelCypheringCreateStatic(
      &keys,
      &CypheringFun);
  unsigned char* cypheredMsg =
    FeistelCypheringCypher(
      &cypher,
      msg,
      strlen((char*)msg));
  printf("Cyphered message: ");
  for (
    unsigned int iChar = 0;
    iChar < strlen((char*)msg);
    ++iChar) {

    printf(
      "%03u,",
      cypheredMsg[iChar]);

  }

  printf("\n");
  unsigned char* decypheredMsg =
    FeistelCypheringDecypher(
      &cypher,
      cypheredMsg,
      strlen((char*)msg));
  int ret =
    strcmp(
      (char*)msg,
      (char*)decypheredMsg);
  if (ret != 0) {

    CrypticErr->_type = PBErrTypeUnitTestFailed;
    sprintf(
      CrypticErr->_msg,
      "FeistelCypheringCypher/FeistelCypheringDecypher NOK");
    PBErrCatch(CrypticErr);

  }

  printf(
    "%s\n",
    decypheredMsg);

  FeistelCypheringFreeStatic(&cypher);
  GSetFlush(&keys);
  free(cypheredMsg);
  free(decypheredMsg);
  printf("UnitTestFeistelCyphering OK\n");

}

void UnitTestAll() {

  UnitTestFeistelCyphering();
  printf("UnitTestAll OK\n");

}

int main() {

  UnitTestAll();

  // Return success code
  return 0;

}
