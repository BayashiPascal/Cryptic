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

int main(
     int argc,
  char** argv) {

  // Declare variables to process arguments
  FILE* fpOut = NULL;
  FILE* fpIn = NULL;
  FILE* fpKeys = NULL;
  FeistelCipheringOpMode opMode = FeistelCipheringOpMode_CTR;

  // Declare the set to memorize the keys
  GSetStr keys = GSetStrCreateStatic();

  // Declare the initial vector
  char initVector[1024] = {'\0'};

  // Loop on arguments
  for (
    int iArg = 1;
    iArg < argc;
    ++iArg) {

    int retStrCmp =
      strcmp(
        argv[iArg],
        "-help");
    if (retStrCmp == 0) {

      printf("cryptic\n");
      printf("[-help] : print the help message\n");
      printf("[-out <path>] : Save the result to the file at <path>\n");
      printf("                If not specified uses stdout\n");
      printf("[-encode <path>] : Encode the file at <path>\n");
      printf("[-decode <path>] : Decode the file at <path>\n");
      printf("-keys <path> : Use the keys in the file at <path>\n");
      printf("               One key per line, must have all the\n");
      printf("               same size (less than 1024 char),\n");
      printf("               the first key is the initial vector\n");
      printf("[-ecb] : Use the ECB op mode\n");
      printf("[-cbc] : Use the CBC op mode\n");
      printf("[-ctr] : Use the CTR op mode (default)\n");
      printf("\n");

    // Else
    } else {

      // If the argument is -out
      unsigned int retStrCmp =
        strcmp(
          argv[iArg],
          "-out");
      if (retStrCmp == 0) {

        // If the output file is opened
        if (fpOut != NULL) {

          // Close it
          fclose(fpOut);

        }

        // Open the file
        fpOut =
          fopen(
            argv[iArg + 1],
            "w");

      }

      // If the argument is -encode
      retStrCmp =
        strcmp(
          argv[iArg],
          "-encode");
      if (retStrCmp == 0) {

        // If the input file is opened
        if (fpIn != NULL) {

          // Close it
          fclose(fpIn);

        }

        // Open the file
        fpIn =
          fopen(
            argv[iArg + 1],
            "r");

        // If the path is incorrect
        if (fpIn == NULL) {

          printf(
            "The path [%s] is incorrect\n",
            argv[iArg + 1]);
          return 1;

        }

        // If the output file is not specified
        if (fpOut == NULL) {

          fpOut =
            fopen(
              "/dev/stdout",
              "w");

        }

        // Create the FeistelCiphering
        FeistelCiphering cipher =
          FeistelCipheringCreateStatic(
            &keys,
            &CipheringFun);
        FeistelCipheringSetOpMode(
          &cipher,
          opMode);

        // Init the ciphering
        FeistelCipheringInitStream(
          &cipher,
          (unsigned char*)initVector);

        // Decipher the file
        FeistelCipheringCipherFile(
          &cipher,
          fpIn,
          fpOut);

        // Free memory
        FeistelCipheringFreeStatic(&cipher);

      }

      // If the argument is -decode
      retStrCmp =
        strcmp(
          argv[iArg],
          "-decode");
      if (retStrCmp == 0) {

        // If the input file is opened
        if (fpIn != NULL) {

          // Close it
          fclose(fpIn);

        }

        // Open the file
        fpIn =
          fopen(
            argv[iArg + 1],
            "r");

        // If the path is incorrect
        if (fpIn == NULL) {

          printf(
            "The path [%s] is incorrect\n",
            argv[iArg + 1]);
          return 1;

        }

        // If the output file is not specified
        if (fpOut == NULL) {

          fpOut =
            fopen(
              "/dev/stdout",
              "w");

        }

        // Create the FeistelCiphering
        FeistelCiphering cipher =
          FeistelCipheringCreateStatic(
            &keys,
            &CipheringFun);
        FeistelCipheringSetOpMode(
          &cipher,
          opMode);

        // Init the ciphering
        FeistelCipheringInitStream(
          &cipher,
          (unsigned char*)initVector);

        // Decipher the file
        FeistelCipheringCipherFile(
          &cipher,
          fpIn,
          fpOut);

        // Free memory
        FeistelCipheringFreeStatic(&cipher);

      }

      // If the argument is -keys
      retStrCmp =
        strcmp(
          argv[iArg],
          "-keys");
      if (retStrCmp == 0) {

        // If the keys file is opened
        if (fpKeys != NULL) {

          // Close it
          fclose(fpKeys);

        }

        // Open the file
        fpKeys =
          fopen(
            argv[iArg + 1],
            "r");

        // If the path is incorrect
        if (fpKeys == NULL) {

          printf(
            "The path [%s] is incorrect\n",
            argv[iArg + 1]);
          return 1;

        }

        // Free eventual previous keys
        while (GSetNbElem(&keys) > 0) {

          char* key = GSetPop(&keys);
          free(key);

        }

        // Load the initial vector
        char* retRead =
          fgets(
            initVector,
            1024,
            fpKeys);
        if (
          retRead == NULL &&
          ferror(fpKeys) != 0) {

          printf(
            "I/O error while loading keys (%d)\n",
            errno);
          return 2;

        }

        int lenInitVector = strlen(initVector);

        // Remove the line feed
        initVector[lenInitVector - 1] = '\0';

        // Load the keys
        while (feof(fpKeys) == false) {

          char* key =
            malloc(
              sizeof(char) * 1024);
          if (key == NULL) {

            printf("malloc failed\n");
            return 3;

          }

          retRead =
            fgets(
              key,
              1024,
              fpKeys);
          if (
            retRead == NULL &&
            ferror(fpKeys) != 0) {

            printf(
              "I/O error while loading keys (%d)\n",
              errno);
            return 2;

          }

          int lenKey = strlen(key);
          if (lenKey > 0) {

            if (lenKey != lenInitVector) {

              printf("All the keys must have the same length\n");
              return 4;

            }

            // Remove the line feed
            key[lenKey - 1] = '\0';

            GSetAppend(
              &keys,
              key);

          }

        }

        if (GSetNbElem(&keys) == 0) {

          printf("No keys in the key file\n");
          return 5;

        }

      }

      // If the argument is -ecb
      retStrCmp =
        strcmp(
          argv[iArg],
          "-ecb");
      if (retStrCmp == 0) {

        // Memorize the operation mode
        opMode = FeistelCipheringOpMode_ECB;

      }

      // If the argument is -cbc
      retStrCmp =
        strcmp(
          argv[iArg],
          "-cbc");
      if (retStrCmp == 0) {

        // Memorize the operation mode
        opMode = FeistelCipheringOpMode_CBC;

      }

      // If the argument is -ctr
      retStrCmp =
        strcmp(
          argv[iArg],
          "-ctr");
      if (retStrCmp == 0) {

        // Memorize the operation mode
        opMode = FeistelCipheringOpMode_CTR;

      }

    }

  }

  // If the keys file is opened
  if (fpKeys != NULL) {

    // Close it
    fclose(fpKeys);

  }

  // If the input file is opened
  if (fpIn != NULL) {

    // Close it
    fclose(fpIn);

  }

  // If the output file is opened
  if (fpOut != NULL) {

    // Close it
    fclose(fpOut);

  }

  // Free memory
  while (GSetNbElem(&keys) > 0) {

    char* key = GSetPop(&keys);
    free(key);

  }

  // Return success code
  return 0;

}
