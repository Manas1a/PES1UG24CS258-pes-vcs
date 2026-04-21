// object.c
// Phase 1: Object Storage
// Implements content-addressable storage using SHA-256 hashing
// Functions:
//  - object_write: stores objects in .pes/objects/
//  - object_read: retrieves and verifies stored objects// sha256 hashing logic
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

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
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

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
// Header
    char header[64];
    const char *type_str =
        (type == OBJ_BLOB) ? "blob" :
        (type == OBJ_TREE) ? "tree" :
        (type == OBJ_COMMIT) ? "commit" : "blob";

    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // Full object = header + data
    size_t full_len = header_len + len;
    unsigned char *full = malloc(full_len);
    if (!full) return -1;

    memcpy(full, header, header_len);
 if (len > 0 && data != NULL)
    memcpy(full + header_len, data, len);

    // Compute hash
    compute_hash(full, full_len, id_out);

    // Deduplication
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Path + directory
    char path[512];
    object_path(id_out, path, sizeof(path));

    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir(dir, 0755);
    }

    // Temp file
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmpXXXXXX", path);

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full);
        return -1;
    }

    // Write
    if (write(fd, full, full_len) != (ssize_t)full_len) {
        close(fd);
        free(full);
        return -1;
    }

    fsync(fd);
    close(fd);

    // Atomic rename
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

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // TODO: Implement
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

    // Find header
    unsigned char *nul = memchr(buf, '\0', file_size);
    if (!nul) {
        free(buf);
        return -1;
    }

    // Parse type
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

    // Parse size
    size_t size;
    sscanf((char *)buf + ((*type_out == OBJ_COMMIT) ? 7 : 5), "%zu", &size);

    // Verify hash
    ObjectID computed;
    compute_hash(buf, file_size, &computed);

    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1;
    }

    // Extract data
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
