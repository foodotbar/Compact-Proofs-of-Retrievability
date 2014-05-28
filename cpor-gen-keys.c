
#include <openssl/rand.h>
#include <stdio.h>
#include "cpor.h"

int main(int argc, char *argv[])
{
    const char *file_name = CPOR_MASTER_KEYS_FILE;
    FILE *file;
    unsigned char kenc[CPOR_ENC_KEY_BYTES];
    unsigned char kmac[CPOR_MAC_KEY_BYTES];

    printf("Generating master keys....\n");
    file = fopen(file_name, "wb");
    if (!file) {
        fprintf(stderr, "Create master keys file failed.\n");
        return -1;
    }
    if (!RAND_bytes(kenc, sizeof(kenc))) {
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    if (!RAND_bytes(kmac, sizeof(kmac))) {
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    if(fwrite(kenc, sizeof(kenc), 1, file) != 1) {
        fprintf(stderr, "fwrite failed.\n");
        return -1;
    }
    if(fwrite(kmac, sizeof(kmac), 1, file) != 1) {
        fprintf(stderr, "fwrite failed.\n");
        return -1;
    }
    fflush(file);
    fclose(file);
    printf("Done.\n");

    return 0;
}

