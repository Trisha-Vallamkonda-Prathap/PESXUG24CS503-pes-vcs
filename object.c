// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).

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

// ─── object_write ────────────────────────────────────────────────────────────
//
// Stores data in the object store.
// Object format on disk: "<type> <size>\0<data>"
//
// Steps:
//   1. Build header string e.g. "blob 16\0"
//   2. Concatenate header + data into one buffer
//   3. Compute SHA-256 of the full buffer → id_out
//   4. If object already exists, return 0 (deduplication)
//   5. Create shard dir (.pes/objects/XX/) if needed
//   6. Write to temp file, fsync, then rename atomically
//   7. fsync the shard directory to persist the rename
//
// Returns 0 on success, -1 on error.

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    char header[64];
    const char *type_str;

    switch (type) {
        case OBJ_BLOB:   type_str = "blob";   break;
        case OBJ_TREE:   type_str = "tree";   break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // Build header: "<type> <size>\0"
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;

    // Allocate full buffer (header + data)
    size_t total_len = header_len + len;
    char *full = malloc(total_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    // Compute hash of full object
    compute_hash(full, total_len, id_out);

    // Deduplication: if already stored, skip writing
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // Build final path and shard directory path
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s", final_path);
    char *slash = strrchr(dir_path, '/');
    if (!slash) { free(full); return -1; }
    *slash = '\0';

    // Create shard directory (ignore error if already exists)
    mkdir(dir_path, 0755);

    // Write to temp file
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmpXXXXXX", dir_path);
    int fd = mkstemp(temp_path);
    if (fd < 0) { free(full); return -1; }

    ssize_t written = write(fd, full, total_len);
    if (written != (ssize_t)total_len) {
        close(fd); unlink(temp_path); free(full); return -1;
    }

    // Flush to disk before rename
    if (fsync(fd) < 0) {
        close(fd); unlink(temp_path); free(full); return -1;
    }
    close(fd);

    // Atomic rename: temp → final
    if (rename(temp_path, final_path) < 0) {
        unlink(temp_path); free(full); return -1;
    }

    // fsync the directory to persist the rename
    int dir_fd = open(dir_path, O_DIRECTORY | O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    free(full);
    return 0;
}

// ─── object_read ─────────────────────────────────────────────────────────────
//
// Reads an object from the store and verifies integrity.
//
// Steps:
//   1. Build path from hash using object_path()
//   2. Open and read the entire file into memory
//   3. Recompute SHA-256 and compare to *id — return -1 if mismatch
//   4. Parse header: "<type> <size>\0"
//   5. Extract the data portion (after the '\0')
//   6. Set *type_out, *data_out, *len_out
//
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // Get file size
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long fsize = ftell(f);
    if (fsize < 0) { fclose(f); return -1; }
    rewind(f);

    // Read entire file
    char *buf = malloc(fsize);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);

    // Integrity check: recompute hash
    ObjectID computed;
    compute_hash(buf, fsize, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf); return -1;
    }

    // Find '\0' separator between header and data
    char *null_pos = memchr(buf, '\0', fsize);
    if (!null_pos) { free(buf); return -1; }

    size_t header_len = null_pos - buf;
    char *data_start  = null_pos + 1;
    size_t data_len   = fsize - (header_len + 1);

    // Parse header: "<type> <size>"
    char type_str[16];
    size_t declared_size;
    if (sscanf(buf, "%15s %zu", type_str, &declared_size) != 2) {
        free(buf); return -1;
    }

    // Validate declared size
    if (declared_size != data_len) { free(buf); return -1; }

    // Convert type string to enum
    if      (strcmp(type_str, "blob")   == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree")   == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;
    else { free(buf); return -1; }

    // Allocate and return data
    void *out = malloc(data_len);
    if (!out) { free(buf); return -1; }
    memcpy(out, data_start, data_len);

    *data_out = out;
    *len_out  = data_len;

    free(buf);
    return 0;
}
