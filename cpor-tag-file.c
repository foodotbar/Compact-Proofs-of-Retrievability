
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
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cpor.h"

// OK, forgive my including .c file directly.
#include "cpor-util.c"

BIGNUM *p;
int n;
BIGNUM *alpha_arr[CPOR_S];
unsigned char kprf[CPOR_PRF_KEY_BYTES];
off_t file_size;

void usage(void)
{
    printf("Usage: cpor-tag-file <file-name>.\n");
}

int write_to_metadata_file(const char *file_name)
{
    FILE *file;
    char *metafile;
    
    metafile = (char *)malloc(strlen(file_name) + strlen(CPOR_META_FILE_SUFFIX) + 1);
    assert(metafile);
    memcpy(metafile, file_name, strlen(file_name));
    strcpy(metafile + strlen(file_name), CPOR_META_FILE_SUFFIX);
    file = fopen(metafile, "wb");
    free(metafile);
    if (!file) {
        fprintf(stderr, "Failed to create metadata file.\n");
        return -1;
    }
    // write p to file.
    if (write_one_Zp_elem(p, file)) {
        fprintf(stderr, "Failed to write p to file.\n");
        goto error;
    }
    // write n to file.
    if (fwrite(&n, sizeof(n), 1, file) != 1) {
        fprintf(stderr, "Failed to write n to file.\n");
        goto error;
    }
    // write kprf to file.
    if (fwrite(kprf, sizeof(kprf), 1, file) != 1) {
        fprintf(stderr, "Failed to write kprf to file.\n");
        goto error;
    }
    // write alpha series to file.
    int i;
    for (i = 0; i < CPOR_S; i++) {
        if (write_one_Zp_elem(alpha_arr[i], file)) {
            fprintf(stderr, "Failed to write alpha series to file.\n");
            goto error;
        }
    }

    fclose(file);
    return 0;
error:
    fclose(file);
    return -1;
}

int generate_metadata_file(const char *file_name)
{
    BN_CTX *ctx;
    int i;

    // Generate p.
    ctx = BN_CTX_new();
    assert(ctx);
    int retries = 64;
    int flag = 0;
    for (i = 0; i < retries; i++) {
        if (BN_generate_prime(p, CPOR_PRIME_BITS, 1, NULL, NULL, NULL, NULL)
            && BN_is_prime(p, BN_prime_checks, NULL, ctx, NULL)
            && (BN_num_bits(p) == CPOR_PRIME_BITS)) {
            flag = 1;
            break;
        }
    }
    BN_CTX_free(ctx);
    if (!flag) {
        fprintf(stderr, "Generate large prime number failed.\n");
        return -1;
    }
    // Generate PRF key
    if (!RAND_bytes(kprf, sizeof(kprf))) {
        fprintf(stderr, "RAND_bytes failed.\n");
        return -1;
    }
    // Generate the alpha series
    for (i = 0; i < CPOR_S; i++) {
        BIGNUM *ptr = alpha_arr[i];
        if (!BN_rand_range(ptr, p)) {
            fprintf(stderr, "BN_rand_range failed.\n");
            return -1;
        }
    }

    return write_to_metadata_file(file_name);
}

BIGNUM *process_one_block(int block_idx, const unsigned char *curr, int block_size)
{
    int j, ret;
    unsigned char mac[CPOR_MAC_OUTPUT_BYTES];
    BIGNUM *sigma = NULL, *f_prf = NULL, *mij = NULL;
    BIGNUM *sigma_alpha_mij = NULL;

    DEBUG_PRINT("processing block #%d.\n", block_idx);

    sigma = BN_new();
    assert(sigma);
    f_prf = BN_new();
    assert(f_prf);
    mij = BN_new();
    assert(mij);
    sigma_alpha_mij = BN_new();
    assert(sigma_alpha_mij);
    BN_CTX *ctx = BN_CTX_new();
    assert(ctx);
    BN_CTX_init(ctx);
    HMAC_CTX mac_ctx;
    HMAC_CTX_init(&mac_ctx);

    // calc the first term.
    HMAC_Init(&mac_ctx, kprf, sizeof(kprf), EVP_sha1());
    HMAC_Update(&mac_ctx, (unsigned char *)&block_idx, sizeof(block_idx));
    unsigned usize;
    HMAC_Final(&mac_ctx, mac, &usize);
    assert(usize == CPOR_MAC_OUTPUT_BYTES);
    f_prf = BN_bin2bn(mac, usize, f_prf);
    assert(f_prf);
    HMAC_CTX_cleanup(&mac_ctx);

    // calc the second term.
    ret = BN_zero(sigma_alpha_mij);
    assert(ret);
    for (j = 0; j < CPOR_S; j++) {
        mij = BN_bin2bn(curr, CPOR_SECTOR_SIZE, mij);
        assert(mij);
        ret = BN_mod_mul(mij, alpha_arr[j], mij, p, ctx);
        assert(ret);
        ret = BN_mod_add(sigma_alpha_mij, sigma_alpha_mij, mij, p, ctx);
        assert(ret);
        curr += CPOR_SECTOR_SIZE;
    }

    // now f_prf holds the first term and sigma_alpha_mij holds the second term.
    ret = BN_mod_add(sigma, f_prf, sigma_alpha_mij, p, ctx);
    assert(ret);

    BN_CTX_free(ctx);
    BN_free(f_prf);
    BN_free(mij);
    BN_free(sigma_alpha_mij);

    return sigma;
}

int generate_tag_file(const char *file_name)
{
    int fd, i;
    void *addr;
    unsigned char *curr;
    FILE *file;
    char *tagfile;
    
    tagfile = (char *)malloc(strlen(file_name) + strlen(CPOR_TAG_FILE_SUFFIX) + 1);
    assert(tagfile);
    memcpy(tagfile, file_name, strlen(file_name));
    strcpy(tagfile + strlen(file_name), CPOR_TAG_FILE_SUFFIX);

    // map the data file into memory.
    fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("open: ");
        return -1;
    }
    addr = (unsigned char *)mmap(NULL, file_size, PROT_READ,
            MAP_PRIVATE, fd, 0);
    if ((void *)addr == MAP_FAILED) {
        perror("mmap: ");
        return -1;
    }
    close(fd);
    // Open the tag file for write.
    file = fopen(tagfile, "wb");
    free(tagfile);
    if (!file) {
        fprintf(stderr, "Failed to create tag file.\n");
        goto error;
    }

    // process each block and write tag to tagfile.
    curr = addr;
    for (i = 0; i < n; i++) {
        BIGNUM *sigma = process_one_block(i, curr, CPOR_BLOCK_SIZE);
        assert(sigma);
        curr += CPOR_BLOCK_SIZE;
        // write sigma to file.
        if (write_one_Zp_elem(sigma, file)) {
            BN_free(sigma);
            goto error;
        }
        BN_free(sigma);
    }

    munmap(addr, file_size);
    return 0;
error:
    munmap(addr, file_size);
    return -1;
}

void init(void)
{
    int i;
    // allocate p
    p = BN_new();
    assert(p);
    // allocate alpha series.
    for (i = 0; i < CPOR_S; i++) {
        BIGNUM *ptr = BN_new();
        assert(ptr);
        alpha_arr[i] = ptr;
    }
}
    
int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage();
        return -1;
    }
    char *file_name = argv[1];
    struct stat st;

    // init global variables.
    init();

    // get the file size.
    if (stat(file_name, &st) < 0) {
        perror("stat: ");
        return -1;
    }
    file_size = st.st_size;
    // How many blocks in the file?
    // n = (file_size + CPOR_BLOCK_SIZE - 1) / CPOR_BLOCK_SIZE;
    n = file_size / CPOR_BLOCK_SIZE;

    DEBUG_PRINT("file_size: %ld KB, blocks: %d.\n", file_size / 1024, n);

    // generate the metadata file.
    printf("Generating metadata file %s%s...", file_name, CPOR_META_FILE_SUFFIX);
    if (generate_metadata_file(file_name)) {
        fprintf(stderr, "Generate metadata file failed.\n");
        return -1;
    }
    printf("Done.\n");

    // generate tag for each block, and write to tag file.
    printf("Generating tag file %s%s...", file_name, CPOR_TAG_FILE_SUFFIX);
    if (generate_tag_file(file_name)) {
        fprintf(stderr, "Generate tag file failed.\n");
        return -1;
    }
    printf("Done.\n");

    return 0;
}

