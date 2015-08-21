#include "openssl/des.h"
#include memory
#include "string.h"

//message + padding
const unsigned char msg[40] = { 0x72, 0xC2, 0x9C, 0x23, 0x71, 0xCC, 0x9B, 0xDB,
                              0x65, 0xB7, 0x79, 0xB8, 0xE8, 0xD3, 0x7B, 0x29,
                              0xEC, 0xC1, 0x54, 0xAA, 0x56, 0xA8, 0x79, 0x9F,
                              0xAE, 0x2F, 0x49, 0x8F, 0x76, 0xED, 0x92, 0xF2,
                              0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//initialization vector
unsigned char iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

unsigned char k0[8] = { 0x79, 0x62, 0xD9, 0xEC, 0xE0, 0x3D, 0x1A, 0xCD };
unsigned char k1[8] = { 0x4C, 0x76, 0x08, 0x9D, 0xCE, 0x13, 0x15, 0x43 };


void print_hex(const unsigned char *bs, int n) {

    for (int i = 0; i < n; i++)
        printf("%02x", bs[i]);
    printf("\n");
}

void des_ecb_crypt(unsigned char* input, unsigned char* output, int encrypt, unsigned char* key) {

    des_key_schedule sched;
    des_set_key((des_cblock *) key, sched);

    DES_ecb_encrypt((const_DES_cblock *)input,
                     (const_DES_cblock *)output,
                     &sched,
                     encrypt);
}

void xor_block(unsigned char* src, unsigned char* dest) {

    for (int x = 0; x < 8; x++) {
       src[x] =  src[x] ^ dest[x];
    }
}

int main(int argc, char* argv[]) {

    unsigned char output[8];
    unsigned char xx[8];
    unsigned char block[8];
    int offset = 0;

    memcpy(xx, iv, 8);

    // Chain and encrypt 5 8-bit blocks
    for (int x = 0; x < 5; x++) {

        memcpy(block, &msg[offset] , 8);
        offset+=8;

        //set xx `xor {xx} {mj}` # chain
        xor_block(xx, block);

        //set xx `des -k {k0} -c {xx}` #encrypt
        des_ecb_crypt(xx, output, DES_ENCRYPT, k0);
        memcpy(xx, output, 8);
    }


    des_ecb_crypt(xx, output, DES_DECRYPT, k1);
    memcpy(xx, output, 8);

    des_ecb_crypt(xx, output, DES_ENCRYPT, k0);
    memcpy(xx, output, 8);

    print_hex(xx, 8);
    return 1;
}
