

int write_one_Zp_elem(BIGNUM *elem, FILE *file)
{
    int count;
    unsigned char buf[CPOR_PRIME_ELEM_BYTES];

    assert(BN_num_bytes(elem) <= CPOR_PRIME_ELEM_BYTES);
    count = BN_bn2bin(elem, buf);
    assert(count == BN_num_bytes(elem));
    if (fwrite(&count, sizeof(count), 1, file) != 1) {
        fprintf(stderr, "Failed to write field element size to file.\n");
        return -1;
    }
    if (fwrite(buf, CPOR_PRIME_ELEM_BYTES, 1, file) != 1) {
        fprintf(stderr, "Failed to write field element to file.\n");
        return -1;
    }

    return 0;
}

BIGNUM *read_one_Zp_elem(FILE *file)
{
    int size;
    unsigned char buf[CPOR_PRIME_ELEM_BYTES];

    // read element size from metadata file.
    if (fread(&size, sizeof(size), 1, file) != 1) {
        fprintf(stderr, "Failed to read size from metadata file.\n");
        return NULL;
    }
    assert(size <= CPOR_PRIME_ELEM_BYTES);
    if (fread(buf, CPOR_PRIME_ELEM_BYTES, 1, file) != 1) {
        fprintf(stderr, "Failed to read p from metadata file.\n");
        return NULL;
    }
    return BN_bin2bn(buf, size, NULL);
}

int load_n_p_from_file(const char *file_name, int *pn, BIGNUM **p)
{
    char *metafile;
    FILE *file;

    // load n & p from thee metadata file.
    metafile = (char *)malloc(strlen(file_name) + strlen(CPOR_META_FILE_SUFFIX) + 1);
    assert(metafile);
    memcpy(metafile, file_name, strlen(file_name));
    strcpy(metafile + strlen(file_name), CPOR_META_FILE_SUFFIX);

    file = fopen(metafile, "rb");
    free(metafile);
    if (!file) {
        fprintf(stderr, "Failed to create metadata file.\n");
        return -1;
    }
    // read p from metadata file.
    *p = read_one_Zp_elem(file);
    assert(*p);
    // read number of blocks from metadata file.
    if (fread(pn, sizeof(*pn), 1, file) != 1) {
        fprintf(stderr, "Failed to read n from metadata file.\n");
        fclose(file);
        return -1;
    }

    return 0;
}

