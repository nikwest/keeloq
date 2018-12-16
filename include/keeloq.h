/*
  Keeloq.h - Crypto library
  Written by Frank Kienast in November, 2010
*/

#ifndef keeloq_h
#define keeloq_h

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct keeloq;

struct keeloq *keeloq_create(const unsigned long keyHigh, const unsigned long keyLow);

unsigned long keeloq_encrypt(struct keeloq *keeloq, const unsigned long data );
unsigned long keeloq_decrypt(struct keeloq *keeloq, const unsigned long data );

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif		/*keeloq_h*/
