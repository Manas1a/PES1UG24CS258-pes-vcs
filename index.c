// phase3: index load implementation
// phase3: index save logic
#include "index.h"
#include "tree.h"
#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

// ─── PROVIDED ─────────────────────────────────────────────────────

IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    return -1;
}

int index_status(const Index *index) {
    printf("Staged changes:\n");
    if (index->count == 0) printf("  (nothing to show)\n");
    for (int i = 0; i < index->count; i++)
        printf("  staged:     %s\n", index->entries[i].path);
    printf("\n");
    return 0;
}

// ─── IMPLEMENTATION ─────────────────────────────────────────────

static int cmp_entries(const void *a, const void *b) {
    return strcmp(((IndexEntry*)a)->path, ((IndexEntry*)b)->path);
}

int index_load(Index *index) {
    index->count = 0;

    FILE *f = fopen(".pes/index", "r");
    if (!f) return 0;

    while (index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *e = &index->entries[index->count];
        char hex[HASH_HEX_SIZE + 1];

        int ret = fscanf(f, "%o %64s %ld %u %255s",
                         &e->mode, hex, &e->mtime_sec, &e->size, e->path);

        if (ret != 5) break;

        if (hex_to_hash(hex, &e->hash) != 0) {
            fclose(f);
            return -1;
        }

        index->count++;
    }

    fclose(f);
    return 0;
}

int index_save(const Index *index) {
    FILE *f = fopen(".pes/index.tmp", "w");
    if (!f) return -1;

    // Heap-allocate the copy to avoid stack overflow (Index is very large)
    Index *temp = malloc(sizeof(Index));
    if (!temp) { fclose(f); return -1; }
    *temp = *index;

    qsort(temp->entries, temp->count, sizeof(IndexEntry), cmp_entries);

    for (int i = 0; i < temp->count; i++) {
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&temp->entries[i].hash, hex);
        fprintf(f, "%o %s %ld %u %s\n",
                temp->entries[i].mode,
                hex,
                temp->entries[i].mtime_sec,
                temp->entries[i].size,
                temp->entries[i].path);
    }

    free(temp);
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (rename(".pes/index.tmp", ".pes/index") != 0)
        return -1;

    return 0;
}

int index_add(Index *index, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t size = st.st_size;
    void *data = NULL;

    if (size > 0) {
        data = malloc(size);
        if (!data) { fclose(f); return -1; }
        if (fread(data, 1, size, f) != size) {
            fclose(f); free(data); return -1;
        }
    }
    fclose(f);

    ObjectID id;
    if (object_write(OBJ_BLOB, data, size, &id) != 0) {
        free(data); return -1;
    }
    free(data);

    IndexEntry *e = index_find(index, path);
    if (!e) {
        if (index->count >= MAX_INDEX_ENTRIES) return -1;
        e = &index->entries[index->count++];
    }

    e->mode     = get_file_mode(path);
    e->hash     = id;
    e->mtime_sec = st.st_mtime;
    e->size     = (unsigned int)st.st_size;
    strncpy(e->path, path, sizeof(e->path) - 1);
    e->path[sizeof(e->path) - 1] = '\0';

    return index_save(index);
}
