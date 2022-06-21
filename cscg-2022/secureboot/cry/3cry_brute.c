#include "stdio.h"
#include "stdlib.h"
#include "string.h"

typedef unsigned char byte;


int success = 0;
int current_keybyte = -1;
byte sbox[256] = { '\xfa', '\xbc', '\x00', '\x7c', '\xbe', '\x00', '\x7c', '\xbf', '\x00', '\x06', '\xb9', '\x80', '\x00', '\xfc', '\xf3', '\x66', '\xa5', '\x66', '\xea', '\x19', '\x06', '\x00', '\x00', '\x00', '\x00', '\xfb', '\xb8', '\x02', '\x02', '\xbb', '\x00', '\x7c', '\xb2', '\x81', '\xb9', '\x01', '\x00', '\xb6', '\x00', '\xcd', '\x13', '\xbf', '\x00', '\x7c', '\x8d', '\x36', '\x64', '\x07', '\x89', '\xf8', '\x8d', '\x3e', '\x6c', '\x07', '\xb9', '\x02', '\x00', '\xf3', '\x66', '\xa5', '\x89', '\xc7', '\x83', '\xee', '\x08', '\x66', '\xe8', '\x55', '\x00', '\x00', '\x00', '\x89', '\xfb', '\x8d', '\x3e', '\x6c', '\x07', '\xb9', '\x08', '\x00', '\x8a', '\x24', '\x8a', '\x05', '\x30', '\xe0', '\x88', '\x04', '\x46', '\x47', '\xe2', '\xf4', '\x89', '\xdf', '\x83', '\xee', '\x08', '\x83', '\xc7', '\x08', '\x89', '\xf8', '\x2d', '\x00', '\x7e', '\x75', '\xc5', '\xbe', '\x00', '\x7e', '\x8d', '\x3e', '\xed', '\x06', '\x66', '\xe8', '\x4a', '\x00', '\x00', '\x00', '\xbe', '\x00', '\x7e', '\x8d', '\x3e', '\x64', '\x07', '\xb9', '\x08', '\x00', '\xf3', '\xa6', '\x75', '\x05', '\xb8', '\x00', '\x7c', '\xff', '\xe0', '\x8d', '\x36', '\x00', '\x07', '\xb4', '\x0e', '\xac', '\x3c', '\x00', '\x0f', '\x84', '\x8c', '\x00', '\xcd', '\x10', '\xeb', '\xf5', '\xb9', '\x00', '\x01', '\xac', '\x4e', '\x31', '\xd2', '\x56', '\x57', '\x01', '\xd7', '\x8a', '\x25', '\x00', '\xe0', '\xbb', '\x00', '\x06', '\xd7', '\x42', '\x83', '\xe2', '\x07', '\x01', '\xd6', '\x8a', '\x24', '\x00', '\xe0', '\xd0', '\xc0', '\x88', '\x04', '\x5f', '\x5e', '\xe2', '\xe2', '\xc3', '\xb9', '\x00', '\x01', '\x56', '\x89', '\xca', '\x4a', '\x83', '\xe2', '\x07', '\x67', '\x8a', '\x24', '\x16', '\x67', '\x8a', '\x04', '\x17', '\xd5', '\x01', '\xbb', '\x00', '\x06', '\xd7', '\x42', '\x83', '\xe2', '\x07', '\x66', '\x01', '\xd6', '\x8a', '\x24', '\xd0', '\xcc', '\x28', '\xc4', '\x88', '\x24', '\x5e', '\xe2', '\xd9', '\xc3', '\x41', '\x00', '\x41', '\x00', '\x41', '\x00', '\x41', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00' };
byte base_payload[512] = { '\x9c', '\x31', '\x2d', '\x5a', '\x4e', '\xfa', '\x10', '\x8c', '\x53', '\x60', '\x8c', '\x64', '\x7b', '\x4a', '\x8d', '\x21', '\xa9', '\xf8', '\x36', '\x77', '\x31', '\x5a', '\x1b', '\x9c', '\xe9', '\x26', '\xea', '\x6b', '\xf4', '\x0e', '\x4f', '\x89', '\x94', '\x64', '\xd0', '\xa8', '\x41', '\xf5', '\x59', '\x2c', '\x7e', '\x4a', '\x60', '\x7a', '\xf8', '\x63', '\x30', '\x10', '\x3d', '\xc9', '\x23', '\x8c', '\xdc', '\x8b', '\xf4', '\xe9', '\x73', '\x71', '\x33', '\xf5', '\x9b', '\x5e', '\xd4', '\xed', '\xef', '\x9a', '\x53', '\xfb', '\x7b', '\x1c', '\xe2', '\x21', '\xe1', '\xe9', '\x92', '\x6e', '\xe2', '\xe1', '\xb0', '\x6a', '\xb5', '\x70', '\xc4', '\xe7', '\xb3', '\x78', '\x40', '\xf2', '\xf3', '\x4f', '\xed', '\x0f', '\xf0', '\x32', '\x36', '\xf5', '\x82', '\xa8', '\xed', '\x0d', '\xf9', '\x27', '\x13', '\x85', '\x17', '\x3b', '\x76', '\x8c', '\xe4', '\x8a', '\x74', '\xad', '\x22', '\xe2', '\x72', '\x04', '\xb3', '\x8a', '\xc0', '\xf5', '\x61', '\xbb', '\xf2', '\xe6', '\xb7', '\x76', '\x35', '\x63', '\xa3', '\xa5', '\x96', '\xaf', '\x2c', '\xe9', '\x8c', '\xa5', '\x61', '\x8e', '\x53', '\x05', '\xc4', '\x26', '\x9e', '\x74', '\x5f', '\x39', '\x65', '\xfa', '\x46', '\xe0', '\x7e', '\x62', '\x1c', '\xae', '\xcb', '\x28', '\x45', '\xa9', '\x61', '\xe2', '\xf2', '\xbb', '\x56', '\x21', '\xa2', '\xc1', '\xda', '\x23', '\x33', '\xc5', '\x9c', '\xad', '\x68', '\x93', '\x8e', '\xb2', '\xa4', '\xc2', '\x95', '\xa7', '\x2d', '\xc0', '\x0b', '\x0a', '\x72', '\xd4', '\x91', '\xc5', '\xf1', '\x7c', '\xbd', '\x8b', '\x0b', '\x7c', '\x3b', '\xfb', '\x2b', '\x0a', '\x5e', '\x7e', '\xc8', '\x62', '\x0a', '\x36', '\xd5', '\x44', '\x1f', '\xb4', '\x08', '\xd3', '\xf1', '\x6d', '\x47', '\x28', '\x62', '\x22', '\xf1', '\xc0', '\xca', '\xd9', '\x99', '\x6c', '\xfd', '\x27', '\x9c', '\x31', '\x52', '\x36', '\x0c', '\x01', '\x89', '\xa2', '\x78', '\x58', '\x1a', '\xe6', '\x4d', '\x67', '\x5c', '\xa7', '\xf7', '\x50', '\x65', '\x1c', '\x3f', '\xd8', '\x3a', '\xc4', '\x58', '\xc5', '\xa0', '\x01', '\x78', '\x98', '\xe0', '\x93', '\xfa', '\xd1', '\x71', '\x9b', '\x04', '\xfb', '\xe0', '\x1f', '\xf4', '\xc9', '\xef', '\x28', '\x60', '\x70', '\x09', '\x3e', '\x08', '\x77', '\xbc', '\x0e', '\xf3', '\x25', '\x23', '\x0b', '\x3a', '\x84', '\x2e', '\xa8', '\xae', '\xc4', '\x02', '\x3f', '\x64', '\xa1', '\x24', '\x38', '\x66', '\x09', '\x06', '\x80', '\x90', '\x7e', '\xf9', '\x46', '\x2b', '\x7a', '\x96', '\x36', '\x72', '\x65', '\xee', '\xa2', '\x3a', '\x6a', '\xcf', '\x69', '\xfe', '\x5b', '\xb1', '\xda', '\x42', '\xf2', '\xc2', '\xc7', '\x56', '\x69', '\x05', '\xd2', '\x8e', '\x51', '\xb8', '\x28', '\x27', '\x6f', '\xf9', '\x31', '\xb2', '\x8f', '\x1d', '\x03', '\x41', '\xf8', '\x96', '\x9e', '\x1d', '\x78', '\x71', '\x2f', '\x7b', '\x2c', '\x76', '\x84', '\xd1', '\xaf', '\x61', '\xc9', '\x76', '\xae', '\xb1', '\xac', '\xb9', '\xad', '\xae', '\xbb', '\xf4', '\x4a', '\xe4', '\x07', '\x77', '\x4d', '\xb8', '\x4e', '\x74', '\xe3', '\xfc', '\xac', '\x19', '\xa1', '\xbf', '\xeb', '\xe5', '\x38', '\xdc', '\xdf', '\xc1', '\xb4', '\x32', '\x93', '\x56', '\xa1', '\x2a', '\x03', '\x83', '\x21', '\x96', '\x07', '\xa1', '\x46', '\x44', '\x12', '\x2b', '\xcc', '\x20', '\x34', '\xf5', '\x5b', '\xa0', '\xa6', '\x65', '\xb0', '\x47', '\x29', '\x8b', '\xc1', '\x58', '\x85', '\xb1', '\xd1', '\x44', '\x28', '\x7c', '\x6b', '\x53', '\xa3', '\xea', '\xad', '\x02', '\x0b', '\xf5', '\x8d', '\xfd', '\xad', '\x29', '\x03', '\x41', '\xb7', '\xf9', '\x9f', '\xf0', '\xe9', '\x6d', '\xd3', '\x1f', '\x4c', '\xfd', '\x1f', '\xa4', '\x61', '\x2e', '\x73', '\xd1', '\x68', '\x01', '\xe5', '\xec', '\x54', '\x0c', '\x63', '\xd8', '\x06', '\x77', '\xe6', '\xd2', '\xa5', '\xf0', '\x8c', '\x60', '\x1d', '\x61', '\x35', '\xcb', '\x71', '\x9d', '\xcd', '\x30', '\x6d', '\xc4', '\x9a', '\x92', '\x17', '\xdb', '\x3d', '\x39', '\xc1', '\xf3', '\x2f', '\x08', '\xc2', '\xf2', '\x04', '\xf0', '\x8a', '\x63', '\xfc', '\x9d', '\xe7', '\x1e', '\xe6', '\xcf', '\x29', '\x2b', '\x3d', '\x2e', '\x65', '\x7c', '\x7e', '\x98', '\xfc', '\x5f', '\xdc', '\x02', '\xda', '\xe9', '\x21', '\x08', '\x2e' };


void decrypt(byte* buf, const byte* key) {
    for (int i = 1; i <= 0x100; i++) {
        byte j = (key[(i - 1) % 8] + buf[(i - 1) % 8]);

        if (j >= 237 && j < 237 + 8) {
            if (current_keybyte == -1) {
                current_keybyte = j;
            } else if (j != current_keybyte) {
                success = 0;
            }
        }

        byte x = buf[i % 8] + sbox[j];
        buf[i % 8] = (x << 1 | x >> 7);
    }
}

void print_hex(byte* buf) {
    for (int i = 0; i < 8; i++) {
        printf("%02hhx ", buf[i]);
    }
    printf("\n");
}

void hash_payload(const byte* payload) {
    byte buf[8] = {0};
    byte tmp[8] = {0};
    for (int i = 0; i < 512 / 8; i++) {
        decrypt(tmp, payload + i * 8);

        for (int j = 0; j < 8; j++) {
            buf[j] = tmp[j] ^ buf[j];
            tmp[j] = buf[j];
        }
    }

    printf("Hash: ");
    print_hex(buf);
}

void find_base_payload() {
    srand(101010101);

    byte key[512] = {0};
    byte buf[8] = {0};
    byte tmp[8] = {0};

    for (int i = 0; i < 512 / 8; i++) {

        while (1) {
            byte tmptmp[8];
            for (int j = 0; j < 8; j++) {
                tmptmp[j] = tmp[j];
            }

            for (int j = 0; j < 8; j++) {
                key[i * 8 + j] = rand() & 0xFF;
            }

            current_keybyte = -1;
            success = 1;
            decrypt(tmptmp, key + i * 8);

            if (success && current_keybyte == -1) {
                printf("Found another stage %d / %d: ", i + 1, 512 / 8);
                print_hex(key + i * 8);
                for (int j = 0; j < 8; j++) {
                    buf[j] = tmptmp[j] ^ buf[j];
                    tmp[j] = buf[j];
                }

                break;
            }
        }
    }

    printf("Finished:\n");
    for (int i = 0; i < 512 / 8; i++) {
        print_hex(key + i * 8);
    }
}

void find_keyleaks() {
    srand(101010101);

    for (int keybyteIdx = 0; keybyteIdx < 8; keybyteIdx++) {

        byte key[512] = {0};
        memcpy(key, base_payload, 512);
        byte buf[8] = {0};
        byte tmp[8] = {0};

        for (int i = 0; i < 512 / 8 - 1; i++) {
            decrypt(tmp, key + i * 8);

            for (int j = 0; j < 8; j++) {
                buf[j] = tmp[j] ^ buf[j];
                tmp[j] = buf[j];
            }
        }


        while (1) {
            const int i = 512 / 8 - 1;

            byte tmptmp[8];
            for (int j = 0; j < 8; j++) {
                tmptmp[j] = tmp[j];
            }

            for (int j = 0; j < 8; j++) {
                key[i * 8 + j] = rand() & 0xFF;
            }

            current_keybyte = -1;
            success = 1;
            decrypt(tmptmp, key + i * 8);

            if (success && current_keybyte - 237 == keybyteIdx) {
                printf("Found key leak for %d: ", keybyteIdx);
                print_hex(key + i * 8);
                break;
            }
        }
    }
}

int main() {
    // payload which is independent of keys
    // find_base_payload();
    // verify: should be independent on key bytes
    // hash_payload(base_payload);
    find_keyleaks();
    return 0;
}
