// compile with:
// gcc -o decode -m32 decode.c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char byte;
typedef unsigned int uint;

void encrypt(byte* address,uint length,byte magic_value)
{
  byte param_4[4] = { 0x0f, 0x53, 0xbd, 0x66 };

  byte magic_val_copy;
  uint counter;
  
  magic_val_copy = magic_value;
  counter = 0;
  while (counter < length) {
    magic_val_copy = magic_val_copy ^ *(byte *)(param_4 + (magic_val_copy & 3));
    *(byte *)(address + counter) = *(char *)(address + counter) + magic_val_copy * magic_val_copy;
    magic_val_copy = *(byte *)(address + counter);
    counter = counter + 1;
  }
  return;
}

void print_possible_keys() {
    uint i;

    byte header[16];
    FILE* f_elf = fopen("happy_fun_binary", "rb");
    fread(header, 1, 16, f_elf);
    fclose(f_elf);

    byte target[16];
    FILE* f_enc = fopen("encrypted.so", "rb");
    fread(target, 1, 16, f_enc);
    fclose(f_enc);

    byte enc[16];
    for(i = 0; i <= 255; ++i) {
        memcpy(enc, header, 16);
        encrypt(enc, 16, (byte)i);
        if(memcmp(enc, target, 16) == 0) {
            printf("%u\n", i);
        }
    }
}

int main(int argc, char** argv) {
    // print_possible_keys();

    uint size = 0x7a78;
    int i;
    byte key_to_test = atoi(argv[1]);
    printf("Testing %u\n", (uint)key_to_test);

    byte encrypted_target[size];
    FILE* f_src = fopen("encrypted.so", "rb");
    fread(encrypted_target, 1, size, f_src);
    fclose(f_src);

    byte decrypted[size];
    memset(decrypted, 0, size);

    byte tmp[size];
    for(i = 0; i < size; ++i) {
        int guess;

        for(guess = 0; guess <= 255; ++guess) {
            memcpy(tmp, decrypted, i + 1);
            tmp[i] = (byte)guess;
            encrypt(tmp, i + 1, key_to_test);
            if(tmp[i] == encrypted_target[i]) {
                break;
            }
        }
        if(guess == 256) {
            printf("Could not find value\n");
            exit(1);
            break;
        }
        // printf("%d\n", guess);
        decrypted[i] = (byte)guess;
    }

    FILE* f_dst = fopen("decrypted.so", "wb");
    fwrite(decrypted, 1, size, f_dst);
    fclose(f_dst);
}
