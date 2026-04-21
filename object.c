// object.c
// Phase 1: Object Storage
// Implements content-addressable storage using SHA-256 hashing

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── YOUR IMPLEMENTATION ─────────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    // create header
    char header[64];
    const char *type_str =
        (type == OBJ_BLOB) ? "blob" :
        (type == OBJ_TREE) ? "tree" :
        (type == OBJ_COMMIT) ? "commit" : "blob";

    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // combine header + data
    size_t full_len = header_len + len;
    unsigned char *full = malloc(full_len);
    if (!full) return -1;

    memcpy(full, header, header_len);

    if (len > 0 && data != NULL) {
        memcpy(full + header_len, data, len);
    }

    // compute SHA-256 hash
    compute_hash(full, full_len, id_out);

    // deduplication
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // create path
    char path[512];
    object_path(id_out, path, sizeof(path));

    // create directory
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }

    // create temp file
    char temp_path[512];
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmpXXXXXX", path) >= (int)sizeof(temp_path)) {
        free(full);
        return -1;
    }

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // write data
    if (write(fd, full, full_len) != (ssize_t)full_len) {
        close(fd);
        free(full);
        return -1;
    }

    fsync(fd);
    close(fd);

    // atomic rename
    if (rename(temp_path, path) != 0) {
        free(full);
        return -1;
    }

    // fsync directory
    int dir_fd = open(dir, O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {

    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    unsigned char *buf = malloc(file_size);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (fread(buf, 1, file_size, f) != (size_t)file_size) {
        fclose(f);
        free(buf);
        return -1;
    }
    fclose(f);

    // find header
    unsigned char *nul = memchr(buf, '\0', file_size);
    if (!nul) {
        free(buf);
        return -1;
    }

    // parse type
    if (strncmp((char *)buf, "blob", 4) == 0)
        *type_out = OBJ_BLOB;
    else if (strncmp((char *)buf, "tree", 4) == 0)
        *type_out = OBJ_TREE;
    else if (strncmp((char *)buf, "commit", 6) == 0)
        *type_out = OBJ_COMMIT;
    else {
        free(buf);
        return -1;
    }

    // parse size
    size_t size;
    sscanf((char *)buf + ((*type_out == OBJ_COMMIT) ? 7 : 5), "%zu", &size);

    // verify hash
    ObjectID computed;
    compute_hash(buf, file_size, &computed);

    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // extract data
    *len_out = size;
    *data_out = malloc(size);
    if (!*data_out) {
        free(buf);
        return -1;
    }

    memcpy(*data_out, nul + 1, size);

    free(buf);
    return 0;
}
