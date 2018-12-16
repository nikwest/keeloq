/*
  Keeloq.cpp - Keeloq encryption/decryption
  Written by Frank Kienast in November, 2010
*/

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "keeloq.h"

#define KeeLoq_NLF              (0x3A5C742EUL)

#define bitRead(value, bit) (((value) >> (bit)) & 0x01)

struct keeloq {
  unsigned long keyHigh;
  unsigned long keyLow;
};

bool mgos_keeloq_init(void) {
  return true;
}

struct keeloq *keeloq_create(const unsigned long keyHigh, const unsigned long keyLow) {
  struct keeloq *k = NULL;

  k = calloc(1, sizeof(*k));
  if (k == NULL) return NULL;

  k->keyHigh = keyHigh;
  k->keyLow = keyLow;

  return k;
}

unsigned long keeloq_encrypt(struct keeloq *keeloq, const unsigned long data ) {
  unsigned long x = data;
  unsigned long r;
  int keyBitNo, index;
  unsigned long keyBitVal,bitVal;

  for ( r = 0; r < 528; r++ )
  {
    keyBitNo = r & 63;
    if(keyBitNo < 32)
      keyBitVal = bitRead(keeloq->keyLow,keyBitNo);
    else
      keyBitVal = bitRead(keeloq->keyHigh,keyBitNo - 32);
    index = 1 * bitRead(x,1) + 2 * bitRead(x,9) + 4 * bitRead(x,20) + 8 * bitRead(x,26) + 16 * bitRead(x,31);
    bitVal = bitRead(x,0) ^ bitRead(x, 16) ^ bitRead(KeeLoq_NLF,index) ^ keyBitVal;
    x = (x>>1) ^ bitVal<<31;
  }
  return x;
}

unsigned long keeloq_decrypt(struct keeloq *keeloq, const unsigned long data ) {
  unsigned long x = data;
  unsigned long r;
  int keyBitNo, index;
  unsigned long keyBitVal,bitVal;

  for (r = 0; r < 528; r++)
  {
    keyBitNo = (15-r) & 63;
    if(keyBitNo < 32)
      keyBitVal = bitRead(keeloq->keyLow,keyBitNo);
    else
      keyBitVal = bitRead(keeloq->keyHigh,keyBitNo - 32);
    index = 1 * bitRead(x,0) + 2 * bitRead(x,8) + 4 * bitRead(x,19) + 8 * bitRead(x,25) + 16 * bitRead(x,30);
    bitVal = bitRead(x,31) ^ bitRead(x, 15) ^ bitRead(KeeLoq_NLF,index) ^ keyBitVal;
    x = (x<<1) ^ bitVal;
  }
  return x;
 }
