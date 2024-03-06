#include <stdio.h>
#include <wmmintrin.h>

void KEY_256_ASSIST_1(__m128i *temp1, __m128i *temp2) {
  __m128i temp4;
  *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
  temp4 = _mm_slli_si128(*temp1, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp1 = _mm_xor_si128(*temp1, temp4);
  *temp1 = _mm_xor_si128(*temp1, *temp2);
}
void KEY_256_ASSIST_2(__m128i *temp1, __m128i *temp3) {
  __m128i temp2, temp4;
  temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
  temp2 = _mm_shuffle_epi32(temp4, 0xaa);
  temp4 = _mm_slli_si128(*temp3, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  temp4 = _mm_slli_si128(temp4, 0x4);
  *temp3 = _mm_xor_si128(*temp3, temp4);
  *temp3 = _mm_xor_si128(*temp3, temp2);
}

void AES_256_Key_Expansion(const unsigned char *userkey, unsigned char *key) {
  __m128i temp1, temp2, temp3;
  __m128i *Key_Schedule = (__m128i *)key;
  temp1 = _mm_loadu_si128((__m128i *)userkey);
  temp3 = _mm_loadu_si128((__m128i *)(userkey + 16));
  Key_Schedule[0] = temp1;
  Key_Schedule[1] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[2] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[3] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[4] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[5] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[6] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[7] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[8] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[9] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[10] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[11] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[12] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[13] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[14] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[15] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x80);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[16] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[17] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x1b);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[18] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[19] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x36);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[20] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[21] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0x6c);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[22] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[23] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0xd8);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[24] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[25] = temp3;
  temp2 = _mm_aeskeygenassist_si128(temp3, 0xab);
  KEY_256_ASSIST_1(&temp1, &temp2);
  Key_Schedule[26] = temp1;
  KEY_256_ASSIST_2(&temp1, &temp3);
  Key_Schedule[27] = temp3;
  // temp2 = _mm_aeskeygenassist_si128(temp3, 0x4d);
  // KEY_256_ASSIST_1(&temp1, &temp2);
  // Key_Schedule[28] = temp1;
}
//    rcon=(rcon<<1)^(0x11b&-(rcon>>7))

// void aes256_enc(unsigned char *plainText, unsigned char *cipherText) {
//   __m128i m = _mm_loadu_si128((__m128i *)plainText);
//   DO_ENC_BLOCK(m, key_schedule);
//   _mm_storeu_si128((__m128i *)cipherText, m);
// }

// void aes256_dec(unsigned char *cipherText, unsigned char *plainText) {
//   __m128i m = _mm_loadu_si128((__m128i *)cipherText);
//   DO_DEC_BLOCK(m, key_schedule);
//   _mm_storeu_si128((__m128i *)plainText, m);
// }

#include <emmintrin.h>
#include <smmintrin.h>

void Rijndael256_encrypt(unsigned char *in, unsigned char *out,
                         unsigned char *Key_Schedule, unsigned long long length,
                         int number_of_rounds) {
  __m128i tmp1, tmp2, data1, data2;
  __m128i RIJNDAEL256_MASK =
      _mm_set_epi32(0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100);
  __m128i BLEND_MASK =
      _mm_set_epi32(0x80000000, 0x80800000, 0x80800000, 0x80808000);
  __m128i *KS = (__m128i *)Key_Schedule;
  int i, j;
  for (i = 0; i < length / 32; i++) { /* loop over the data blocks */
    data1 = _mm_loadu_si128(&((__m128i *)in)[i * 2 + 0]); /* load data block */
    data2 = _mm_loadu_si128(&((__m128i *)in)[i * 2 + 1]);
    data1 = _mm_xor_si128(data1, KS[0]); /* round 0 (initial xor) */
    data2 = _mm_xor_si128(data2, KS[1]);
    /* Do number_of_rounds-1 AES rounds */
    for (j = 1; j < number_of_rounds; j++) {
      /*Blend to compensate for the shift rows shifts bytes between two
      128 bit blocks*/
      tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
      tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
      /*Shuffle that compensates for the additional shift in rows 3 and 4
      as opposed to rijndael128 (AES)*/
      tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
      tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
      /*This is the encryption step that includes sub bytes, shift rows,
      mix columns, xor with round key*/
      data1 = _mm_aesenc_si128(tmp1, KS[j * 2]);
      data2 = _mm_aesenc_si128(tmp2, KS[j * 2 + 1]);
    }
    tmp1 = _mm_blendv_epi8(data1, data2, BLEND_MASK);
    tmp2 = _mm_blendv_epi8(data2, data1, BLEND_MASK);
    tmp1 = _mm_shuffle_epi8(tmp1, RIJNDAEL256_MASK);
    tmp2 = _mm_shuffle_epi8(tmp2, RIJNDAEL256_MASK);
    tmp1 = _mm_aesenclast_si128(tmp1, KS[j * 2 + 0]); /*last AES round */
    tmp2 = _mm_aesenclast_si128(tmp2, KS[j * 2 + 1]);
    _mm_storeu_si128(&((__m128i *)out)[i * 2 + 0], tmp1);
    _mm_storeu_si128(&((__m128i *)out)[i * 2 + 1], tmp2);
  }
}

void aes256_self_test(void) {
  unsigned char key_schedule[448];
  // static __m128i temp[14];
  // static __m128i temp1[2];
  unsigned char plain[32];
  for(int i=0;i<sizeof(key_schedule);i++) key_schedule[i]=0;
  unsigned char enc_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

  AES_256_Key_Expansion(enc_key, key_schedule);
  // temp[0]=key_schedule[13];

  // AES_256_Key_Expansion(, unsigned char *key)

  unsigned char computed_cipher[32];
  unsigned char computed_plain[32];
  int out = 0;

  printf("Enter plaintext (16 characters): ");
  scanf("%s", plain);

  Rijndael256_encrypt(plain, computed_cipher, key_schedule, 32, 14);

  // int input_length = strlen((const char *)plain);
  // if (input_length < 16) {
  //   memset(plain + input_length, 0, 16 - input_length);
  // }

  // aes256_load_key(enc_key);
  // aes256_enc(plain, computed_cipher);
  // aes256_dec(computed_cipher, computed_plain);

  printf("Computed Cipher: ");
  for (int i = 0; i < sizeof(computed_cipher); i++) {
    printf("%02x ", computed_cipher[i]);
  }
  printf("\n");

  // printf("Computed Plain Text: ");
  // for (int i = 0; i < sizeof(computed_plain); i++) {
  //   printf("%c", computed_plain[i]);
  // }
  // printf("\n");

  // if (memcmp(plain, computed_plain, sizeof(plain))) {
  //   out |= 2;
  // }
  printf("\n");
  printf("%ld", sizeof(key_schedule));

  // printf("computed 256 key:\n");
  // for (int i = 0; i < sizeof(key_schedule) / (8*4); i++) {
  //   printf("%08X\n", *(int *)(&key_schedule[i]));
  // }

  printf("computed 256 key:\n");
  for (int i = 0; i < sizeof(key_schedule); i++) {
    printf("%x\n", *(unsigned char*)(&key_schedule[i]));
  }

  // return out;
}

int main() {
   aes256_self_test();
  // printf("Test Result: %d\n", result);
  return 0;
}
