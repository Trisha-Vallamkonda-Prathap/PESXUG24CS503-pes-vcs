// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

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
    // TODO: Implement
    (void)type; (void)data; (void)len; (void)id_out;
    // 1. Prepare the header: "type size\0"
    char header[64];
    int header_len = snprintf(header, sizeof(header), "%s %ld", type, size);
    header[header_len++] = '\0'; 

    // 2. Compute SHA-256 hash of (header + data)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, header, header_len);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(hash, &sha256);

    // Store the hex string in sha256_hex
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&sha256_hex[i * 2], "%02x", hash[i]);
    }
    // 3. Determine storage path (.pes/objects/XX/YYYY...)
    char dir_path[PATH_MAX];
    char file_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), ".pes/objects/%.2s", sha256_hex);
    snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, sha256_hex + 2);

    // Create the sharded directory structure
    mkdir(".pes", 0755);
    mkdir(".pes/objects", 0755);
    mkdir(dir_path, 0755);
    // 4. Write atomically using temp file
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s/tmp_XXXXXX", dir_path);
    int fd = mkstemp(temp_path);
    if (fd < 0) return -1;

    write(fd, header, header_len);
    write(fd, data, size);
    close(fd);

    if (rename(temp_path, file_path) < 0) {
        unlink(temp_path);
        return -1;
    }
    return 0;
    return -1;
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
    char hash_hex[HASH_HEX_SIZE];
    hash_to_hex(id, hash_hex); // Convert ObjectID to hex string for the path

    char file_path[PATH_MAX];
    snprintf(file_path, sizeof(file_path), ".pes/objects/%.2s/%s", hash_hex, hash_hex + 2);

    FILE *f = fopen(file_path, "rb");
    if (!f) return -1;

    // Get total file size
    fseek(f, 0, SEEK_END);
    long total_size = ftell(f);
    rewind(f);

    unsigned char *content = malloc(total_size);
    if (!content) { fclose(f); return -1; }
    fread(content, 1, total_size, f);
    fclose(f);

    // Locate the null byte separating header "type size\0" from raw data
    char *null_byte = memchr(content, '\0', total_size);
    if (!null_byte) {
        free(content);
        return -1;
    }

    // Parse the header
    char type_str[16];
    size_t size;
    sscanf((char *)content, "%s %zu", type_str, &size);

    // Map string type to ObjectType enum
    if (strcmp(type_str, "blob") == 0) *type_out = OBJ_BLOB;
    else if (strcmp(type_str, "tree") == 0) *type_out = OBJ_TREE;
    else if (strcmp(type_str, "commit") == 0) *type_out = OBJ_COMMIT;

    // Copy the actual data portion
    *data_out = malloc(size);
    if (!*data_out) { free(content); return -1; }
    
    memcpy(*data_out, null_byte + 1, size);
    *len_out = size;

    free(content);
    return 0;
}
