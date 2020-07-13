#include "hash_tab.h"
#include "stdlib.h"
#include "stdio.h"

const struct bpf_map_ops htab_map_ops;

int main() {
    union bpf_attr ba = {
        .map_type = BPF_MAP_TYPE_HASH,
        .key_size = 4,
        .value_size = 5,
        .max_entries = 64,
        .map_flags = BPF_F_NO_PREALLOC
    };

    struct bpf_map *bm = htab_map_ops.map_alloc(&ba);

    char key1[] = "123";
    char value1[] = "123v";
    char key2[] = "456";
    char value2[] = "456v";
    char *result;

    htab_map_ops.map_update_elem(bm, key1, value1, bm->map_flags);
    result = (char *)htab_map_ops.map_lookup_elem(bm, key1);
    printf("key1-> %s\n", result);
    htab_map_ops.map_update_elem(bm, key1, value2, bm->map_flags);
    result = (char *)htab_map_ops.map_lookup_elem(bm, key1);
    printf("key1-> %s\n", result);

    htab_map_ops.map_update_elem(bm, key2, value2, bm->map_flags);
    result = (char *)htab_map_ops.map_lookup_elem(bm, key2);
    printf("key2-> %s\n", result);
    htab_map_ops.map_update_elem(bm, key2, value1, bm->map_flags);
    result = (char *)htab_map_ops.map_lookup_elem(bm, key2);
    printf("key2-> %s\n", result);

    htab_map_ops.map_free(bm);

    printf("here\n");

    return 0;
}