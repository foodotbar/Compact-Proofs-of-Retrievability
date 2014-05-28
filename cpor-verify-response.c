
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

// global information
BIGNUM *p;
int n;
// per-file secrets
BIGNUM *alpha_arr[CPOR_S];
unsigned char kprf[CPOR_PRF_KEY_BYTES];
// challenge
int l;
int *idx;
BIGNUM **v_arr;
// response
BIGNUM *sigma_resp;
BIGNUM *miu_arr[CPOR_S];

void usage(void)
{
    printf("Usage: cpor-verify-response <file-name>.\n");
}

int load_alpha_series_and_kprf(const char *file_name)
{
    char *metafile;
    FILE *file;
    int i;

    metafile = (char *)malloc(strlen(file_name) + strlen(CPOR_META_FILE_SUFFIX) + 1);
    assert(metafile);
    memcpy(metafile, file_name, strlen(file_name));
    strcpy(metafile + strlen(file_name), CPOR_META_FILE_SUFFIX);
    file = fopen(metafile, "rb");
    free(metafile);
    if (!file) {
        fprintf(stderr, "Failed to open metadata file.\n");
        return -1;
    }
    // skip p & n;
    long offset = sizeof(int) + CPOR_PRIME_ELEM_BYTES + sizeof(int);
    if (fseek(file, offset, SEEK_SET)) {
        fprintf(stderr, "fseek failed.\n");
        goto error;
    }
    // load kprf
    if (fread(kprf, sizeof(kprf), 1, file) != 1) {
        fprintf(stderr, "Failed to read kprf from metadata file.\n");
        goto error;
    }
    // load alpha series
    for (i = 0; i < CPOR_S; i++) {
        alpha_arr[i] = read_one_Zp_elem(file);
        assert(alpha_arr[i]);
    }

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
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
    DEBUG_PRINT("challenge length: %d\n", l);
    // read the indices.
    idx = malloc(sizeof(*idx) * l);
    assert(idx);
    for (i = 0; i < l; i++) {
        if (fread(&idx[i], sizeof(idx[i]), 1, file) != 1) {
            fprintf(stderr, "Failed to read challenge idx from challenge file.\n");
            goto error;
        }
    }
    DEBUG_PRINT("challenge block indices: ");
    for (i = 0; i < l; i++) {
        DEBUG_PRINT("%d, ", idx[i]);
    }
    // read the challenge coefficients.
    v_arr = malloc(sizeof(*v_arr) * l);
    assert(v_arr);
    for (i = 0; i < l; i++) {
        v_arr[i] = read_one_Zp_elem(file);
        assert(v_arr[i]);
    }

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
}

int load_respone(const char *file_name)
{
    char *respfile;
    FILE *file;
    int i;

    // open the response file.
    respfile = (char *)malloc(strlen(file_name) + strlen(CPOR_RESPONSE_FILE_SUFFIX) + 1);
    assert(respfile);
    memcpy(respfile, file_name, strlen(file_name));
    strcpy(respfile + strlen(file_name), CPOR_RESPONSE_FILE_SUFFIX);
    file = fopen(respfile, "rb");
    free(respfile);
    if (!file) {
        fprintf(stderr, "Failed to open challenge file.\n");
        return -1;
    }

    // load the response length;
    int l_resp;
    // read l from the file.
    if (fread(&l_resp, sizeof(l_resp), 1, file) != 1) {
        fprintf(stderr, "Failed to read length from challenge file.\n");
        goto error;
    }
    assert(l_resp == l);
    // load sigma in the response.
    sigma_resp = read_one_Zp_elem(file);
    assert(sigma_resp);
    // load the response coefficients.
    for (i = 0; i < CPOR_S; i++) {
        miu_arr[i] = read_one_Zp_elem(file);
        assert(miu_arr[i]);
    }

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
}

int verify_response(const char *file_name)
{
    int i, ret;

    // load n & p from the metata file.
    if (load_n_p_from_file(file_name, &n, &p)) {
        fprintf(stderr, "Failed to load n & p from metadata file.\n");
        return -1;
    }
    DEBUG_PRINT("n: %d\n", n);

    // load the alpha series and kprf from the metadata file.
    if (load_alpha_series_and_kprf(file_name)) {
        fprintf(stderr, "Failed to load alpha series from metadata file.\n");
        return -1;
    }
    // load the challenge sequence.
    if (load_challenge_sequence(file_name)) {
        fprintf(stderr, "Failed to load challenge from challenge file.\n");
        return -1;
    }
    // load the response.
    if (load_respone(file_name)) {
        fprintf(stderr, "Failed to load response from response file.\n");
        return -1;
    }
    // calc sigma_verify
    BIGNUM *sigma_verify = BN_new();
    assert(sigma_verify);
    ret = BN_zero(sigma_verify);
    assert(ret);
    BN_CTX *ctx = BN_CTX_new();
    assert(ctx);
    BN_CTX_init(ctx);

    // the first term.
    BIGNUM *f_prf = BN_new();
    assert(f_prf);
    unsigned char mac[CPOR_MAC_OUTPUT_BYTES];
    HMAC_CTX mac_ctx;
    HMAC_CTX_init(&mac_ctx);
    for (i = 0; i < l; i++) {
        int block_idx = idx[i];
        HMAC_Init(&mac_ctx, kprf, sizeof(kprf), EVP_sha1());
        HMAC_Update(&mac_ctx, (unsigned char *)&block_idx, sizeof(block_idx));
        unsigned usize;
        HMAC_Final(&mac_ctx, mac, &usize);
        assert(usize == CPOR_MAC_OUTPUT_BYTES);
        f_prf = BN_bin2bn(mac, usize, f_prf);
        assert(f_prf);
        ret = BN_mod_mul(f_prf, f_prf, v_arr[i], p, ctx);
        assert(ret);
        ret = BN_mod_add(sigma_verify, sigma_verify, f_prf, p, ctx);
        assert(ret);
    }
    HMAC_CTX_cleanup(&mac_ctx);
    BN_free(f_prf);

    // the second term.
    BIGNUM *temp = BN_new();
    assert(temp);
    for (i = 0; i < CPOR_S; i++) {
        ret = BN_mod_mul(temp, alpha_arr[i], miu_arr[i], p, ctx);
        assert(ret);
        ret = BN_mod_add(sigma_verify, sigma_verify, temp, p, ctx);
        assert(ret);
    }
    BN_free(temp);
    BN_CTX_free(ctx);

    // Check for equality of sigma_verify & sigma_resp
    ret = BN_cmp(sigma_verify, sigma_resp) == 0 ? 1 : 0;
    BN_free(sigma_verify);
    return ret;
}

int main (int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }
    char *file_name = argv[1];

    // verify the response.
    printf("Verify response for file %s...", file_name);
    int ret = verify_response(file_name);
    if (ret == 1)
        printf("Confirmed.\n");
    else if (ret == 0)
        printf("Cheating.\n");
    else printf("Error occurred when verifying.\n");

    return 0;
}

