
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include "cpor.h"

// OK, forgive my including .c file directly.
#include "cpor-util.c"

int n;
BIGNUM *p;

void usage(void)
{
    printf("Usage: cpor-tag-file <file-name>.\n");
}

// generate k different random numbers in [0, n).
// see Programming Perls, exercise 1.4.
void gen_diff_rand_num(int *arr, int n, int k)
{
    int i;
    assert(0 < k && k < n);
    for (i = 0; i < n; i++)
        arr[i] = i;
    srand(time(0));
    for (i = 0; i < k; i++) {
        int rand_idx = rand() % (n - i) + i;
        int temp = arr[i];
        arr[i] = arr[rand_idx];
        arr[rand_idx] = temp;
    }
}
int generate_challenge_file(const char *file_name)
{
    char *chafile;
    FILE *file = NULL;
    int i, l;

    // load n & p from metadata file.
    if (load_n_p_from_file(file_name, &n, &p))
        return -1;

    DEBUG_PRINT("total blocks: %d\n", n);

    // generate the challenge length.
    srand(time(0));
    l = rand() % (n / 4); // at most 1/4 of the file.
    if (l < 1) // at least 1 block;
        l = 1;
    // generate the sequence.
    int *idx;
    BIGNUM **v_arr;
    idx = malloc(sizeof(int) * n);
    assert(idx);
    gen_diff_rand_num(idx, n, l);
    v_arr = malloc(sizeof(*v_arr) * l);
    for (i = 0; i < l; i++) {
        BIGNUM *ptr = BN_new();
        assert(ptr);
        int ret = BN_rand_range(ptr, p);
        assert(ret);
        v_arr[i] = ptr;
    }

    // open the challenge file.
    chafile = (char *)malloc(strlen(file_name) + strlen(CPOR_CHALLENGE_FILE_SUFFIX) + 1);
    assert(chafile);
    memcpy(chafile, file_name, strlen(file_name));
    strcpy(chafile + strlen(file_name), CPOR_CHALLENGE_FILE_SUFFIX);
    file = fopen(chafile, "wb");
    free(chafile);
    if (!file) {
        fprintf(stderr, "Failed to create challenge file.\n");
        return -1;
    }
    // write them to the challenge file.
    DEBUG_PRINT("challenge length l: %d\n", l);
    if (fwrite(&l, sizeof(l), 1, file) != 1) {
        fprintf(stderr, "Failed to write challenge length to challenge file.\n");
        goto error;
    }
    DEBUG_PRINT("challenge block indices: ");
    for (i = 0; i < l; i++) {
        DEBUG_PRINT("%d, ", idx[i]);
    }
    DEBUG_PRINT("\n");
    for (i = 0; i < l; i++) {
        if (fwrite(&idx[i], sizeof(idx[i]), 1, file) != 1) {
            fprintf(stderr, "Failed to write challenge indices to challenge file.\n");
            goto error;
        }
    }
    for (i = 0; i < l; i++) {
        if (write_one_Zp_elem(v_arr[i], file)) {
            fprintf(stderr, "Failed to write challenge coefficients to challenge file.\n");
            goto error;
        }
    }

    // free the resources
    for (i = 0; i < l; i++)
        BN_free(v_arr[i]);
    free(idx);
    free(v_arr);
    BN_free(p);
    fclose(file);
    return 0;
error:
    // free the resources
    for (i = 0; i < l; i++)
        BN_free(v_arr[i]);
    free(idx);
    free(v_arr);
    BN_free(p);
    fclose(file);
    return -1;
}
int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }
    char *file_name = argv[1];

    // generate the challenge file.
    printf("Generating challenge file %s%s for file %s...",
            file_name, CPOR_CHALLENGE_FILE_SUFFIX, file_name);
    if (generate_challenge_file(file_name)) {
        fprintf(stderr, "Generate challenge file failed.\n");
        return -1;
    }
    printf("Done.\n");

    return 0;
}
