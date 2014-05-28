
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cpor.h"

// OK, forgive my including .c file directly.
#include "cpor-util.c"

BIGNUM *p;
int n, l;
int *idx;
BIGNUM **v_arr;

void usage(void)
{
    printf("Usage: cpor-calc-response <file-name>.\n");
}

int load_challenge_sequence(const char *file_name) 
{
    char *chafile;
    FILE *file;
    int i;

    // open the challenge file.
    chafile = (char *)malloc(strlen(file_name) + strlen(CPOR_CHALLENGE_FILE_SUFFIX) + 1);
    assert(chafile);
    memcpy(chafile, file_name, strlen(file_name));
    strcpy(chafile + strlen(file_name), CPOR_CHALLENGE_FILE_SUFFIX);
    file = fopen(chafile, "rb");
    free(chafile);
    if (!file) {
        fprintf(stderr, "Failed to open challenge file.\n");
        return -1;
    }
    // read l from the file.
    if (fread(&l, sizeof(l), 1, file) != 1) {
        fprintf(stderr, "Failed to read length from challenge file.\n");
        goto error;
    }
    // read the indices.
    idx = malloc(sizeof(*idx) * l);
    assert(idx);
    for (i = 0; i < l; i++) {
        if (fread(&idx[i], sizeof(idx[i]), 1, file) != 1) {
            fprintf(stderr, "Failed to read challenge idx from challenge file.\n");
            goto error;
        }
    }
    // read the challenge coefficients.
    v_arr = malloc(sizeof(*v_arr) * l);
    assert(idx);
    for (i = 0; i < l; i++) {
        v_arr[i] = read_one_Zp_elem(file);
        assert(v_arr[i]);
    }

    DEBUG_PRINT("challenge length: %d.\n", l);
    DEBUG_PRINT("challenge block indices: ");
    for (i = 0; i < l; i++) {
        DEBUG_PRINT("%d, ", idx[i]);
    }
    DEBUG_PRINT("\n");

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
}

BIGNUM *load_this_tag(FILE *file, int idx)
{
    long offset = idx * (CPOR_PRIME_ELEM_BYTES + sizeof(int));
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "fseek failed.\n");
        return NULL;
    }
    return read_one_Zp_elem(file);
}

// load j-th sector of i-th block in the file, all starting from 0.
BIGNUM *load_this_sector(FILE *datafile, int i, int j)
{
    long offset = i * CPOR_BLOCK_SIZE + j * CPOR_SECTOR_SIZE;
    unsigned char buf[CPOR_SECTOR_SIZE];

    DEBUG_PRINT("load_this_sector(%d, %d).\n", i, j);

    if (fseek(datafile, offset, SEEK_SET)) {
        fprintf(stderr, "fseek failed.\n");
        return NULL;
    }
    if (fread(buf, CPOR_SECTOR_SIZE, 1, datafile) != 1) {
        fprintf(stderr, "Failed to read sector from data file.\n");
        return NULL;
    }
    return BN_bin2bn(buf, CPOR_SECTOR_SIZE, NULL);
}

BIGNUM *calc_sigma(const char *file_name)
{
    char *tagfile;
    FILE *file;
    int i, ret;

    // open the tag file.
    tagfile = malloc(strlen(file_name) + strlen(CPOR_TAG_FILE_SUFFIX) + 1);
    assert(tagfile);
    memcpy(tagfile, file_name, strlen(file_name));
    strcpy(tagfile + strlen(file_name), CPOR_TAG_FILE_SUFFIX);
    file = fopen(tagfile, "rb");
    free(tagfile);
    if (!file) {
        fprintf(stderr, "Failed to open tag file.\n");
        return NULL;
    }

    BIGNUM *sigma = NULL, *sigma_i;
    sigma = BN_new();
    assert(sigma);
    BN_CTX *ctx = BN_CTX_new();
    assert(ctx);
    BN_CTX_init(ctx);

    ret = BN_zero(sigma);
    assert(ret);
    for (i = 0; i < l; i++) {
        sigma_i = load_this_tag(file, idx[i]);
        assert(sigma_i);
        ret = BN_mod_mul(sigma_i, sigma_i, v_arr[i], p, ctx);
        assert(ret);
        ret = BN_mod_add(sigma, sigma, sigma_i, p, ctx);
        assert(ret);
        BN_free(sigma_i);
    }
    BN_CTX_free(ctx);
    return sigma;
}

int generate_response_file(const char *file_name)
{
    char *respfile;
    FILE *datafile, *file;
    int i, j, ret;

    datafile = fopen(file_name, "rb");
    if (!datafile) {
        fprintf(stderr, "Failed to open data file.\n");
        return -1;
    }
    // create the response file.
    respfile = (char *)malloc(strlen(file_name) + strlen(CPOR_RESPONSE_FILE_SUFFIX) + 1);
    assert(respfile);
    memcpy(respfile, file_name, strlen(file_name));
    strcpy(respfile + strlen(file_name), CPOR_RESPONSE_FILE_SUFFIX);
    file = fopen(respfile, "wb");
    free(respfile);
    if (!file) {
        fprintf(stderr, "Failed to create response file.\n");
        return -1;
    }

    BIGNUM *sigma = calc_sigma(file_name);
    assert(sigma);

    BN_CTX *ctx = BN_CTX_new();
    assert(ctx);
    BN_CTX_init(ctx);
    BIGNUM *miu_j = BN_new();
    assert(miu_j);

    // load the challenge sequence.
    if (load_challenge_sequence(file_name))
        goto error;
    // write the challenge length to file.
    if (fwrite(&l, sizeof(l), 1, file) != 1) {
        fprintf(stderr, "Failed to write length to response file.\n");
        goto error;
    }
    // load p from the metata file.
    load_n_p_from_file(file_name, &n, &p);

    // calc sigma & miu series.
    // calc sigma
    sigma = calc_sigma(file_name);
    // write sigma to response file.
    if (write_one_Zp_elem(sigma, file)) {
        fprintf(stderr, "Failed to write sigma to response file.\n");
        goto error;
    }
    // calc the miu series, and write to response file.
    for (j = 0; j < CPOR_S; j++) {
        ret = BN_zero(miu_j);
        assert(ret);
        for (i = 0; i < l; i++) {
            BIGNUM *mij = load_this_sector(datafile, idx[i], j);
            assert(mij);
            ret = BN_mod_mul(mij, mij, v_arr[i], p, ctx);
            assert(ret);
            ret = BN_mod_add(miu_j, miu_j, mij, p, ctx);
            assert(ret);
            BN_free(mij);
        }
        // write sigma to response file.
        if (write_one_Zp_elem(miu_j, file)) {
            fprintf(stderr, "Failed to write miu to response file.\n");
            goto error;
        }
    }
    BN_free(sigma);
    BN_free(miu_j);
    BN_CTX_free(ctx);
    fclose(file);
    fclose(datafile);
    return 0;
error:
    BN_free(sigma);
    BN_free(miu_j);
    BN_CTX_free(ctx);
    fclose(file);
    fclose(datafile);
    return -1;
}

int main (int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }
    char *file_name = argv[1];

    // generate the response file.
    printf("Generating response file %s%s for file %s...",
            file_name, CPOR_RESPONSE_FILE_SUFFIX, file_name);
    if (generate_response_file(file_name)) {
        fprintf(stderr, "Generate response file failed.\n");
        return -1;
    }
    printf("Done.\n");

    return 0;
}

