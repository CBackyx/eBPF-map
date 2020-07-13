#include "pthread.h"
#include "hash_tab.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

struct bucket {
	struct hlist_nulls_head head;
	pthread_mutex_t lock;
};

struct bpf_htab {
	struct bpf_map map;
	struct bucket *buckets;
	void *elems;

	struct freelist freelist;

	struct htab_elem *extra_elems;
	u32 count;	/* number of elements in this hashtable */
	pthread_mutex_t count_lock;
	u32 n_buckets;	/* number of hash buckets */
	u32 elem_size;	/* size of each element in bytes */
	u32 hashrnd;
};

void atomic_dec_count(struct bpf_htab *htab);

void atomic_inc_count(struct bpf_htab *htab);

u32 atomic_inc_count_return(struct bpf_htab *htab);

/* each htab element is struct htab_elem + key + value */
struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct bpf_htab *htab;
				struct freelist_node fnode;
			};
		}; 	
	};

	u32 hash;
	char key[0];
};

static bool htab_is_prealloc(const struct bpf_htab *htab)
{
	return !(htab->map.map_flags & BPF_F_NO_PREALLOC);
}

static struct htab_elem *get_htab_elem(struct bpf_htab *htab, int i)
{
	return (struct htab_elem *) (htab->elems + i * htab->elem_size);
}

static void htab_free_elems(struct bpf_htab *htab)
{
	free(htab->elems);
}

static int prealloc_init(struct bpf_htab *htab)
{
	u32 num_entries = htab->map.max_entries;
	int err = -ENOMEM, i;

	num_entries += 1;

	htab->elems = malloc(htab->elem_size * num_entries);
	if (!htab->elems)
		return -ENOMEM;

skip_percpu_elems:
	err = freelist_init(&htab->freelist);

	if (err)
		goto free_elems;

	freelist_populate(&htab->freelist,
				       htab->elems + offsetof(struct htab_elem, fnode),
				       htab->elem_size, num_entries);

	return 0;

free_elems:
	htab_free_elems(htab);
	return err;
}

static void prealloc_destroy(struct bpf_htab *htab)
{
	htab_free_elems(htab);

	freelist_destroy(&htab->freelist);
}

static int alloc_extra_elems(struct bpf_htab *htab)
{
	struct htab_elem *l_new;
	struct freelist_node *l;
	int cpu;

	l = freelist_pop(&htab->freelist);
	/* pop will succeed, since prealloc_init()
		* preallocated extra num_possible_cpus elements
		*/
	l_new = container_of(l, struct htab_elem, fnode);

	htab->extra_elems = l_new;
	return 0;
}

/* Called from syscall */
static int htab_map_alloc_check(union bpf_attr *attr)
{
	/* percpu_lru means each cpu has its own LRU list.
	 * it is different from BPF_MAP_TYPE_PERCPU_HASH where
	 * the map's value itself is percpu.  percpu_lru has
	 * nothing to do with the map's value.
	 */
	bool prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);

	/* check sanity of attributes.
	 * value_size == 0 may be allowed in the future to use map as a set
	 */
	if (attr->max_entries == 0 || attr->key_size == 0 ||
	    attr->value_size == 0)
		return -EINVAL;

	if (attr->key_size > MAX_BPF_STACK)
		/* eBPF programs initialize keys on stack, so they cannot be
		 * larger than max stack size
		 */
		return -E2BIG;

	if (attr->value_size >= KMALLOC_MAX_SIZE -
	    MAX_BPF_STACK - sizeof(struct htab_elem))
		/* if value_size is bigger, the user space won't be able to
		 * access the elements via bpf syscall. This check also makes
		 * sure that the elem_size doesn't overflow and it's
		 * kmalloc-able later in htab_map_update_elem()
		 */
		return -E2BIG;

	return 0;
}

static struct bpf_map *htab_map_alloc(union bpf_attr *attr)
{
	/* percpu_lru means each cpu has its own LRU list.
	 * it is different from BPF_MAP_TYPE_PERCPU_HASH where
	 * the map's value itself is percpu.  percpu_lru has
	 * nothing to do with the map's value.
	 */
	bool prealloc = !(attr->map_flags & BPF_F_NO_PREALLOC);
	struct bpf_htab *htab;
	int err, i;
	u64 cost;

	htab = (struct bpf_htab*)malloc(sizeof(*htab));
	if (!htab)
		return NULL;

	pthread_mutex_init(&htab->count_lock, NULL);

	bpf_map_init_from_attr(&htab->map, attr);

	/* hash table size must be power of 2 */
	htab->n_buckets = roundup_pow_of_two(htab->map.max_entries);

	htab->elem_size = sizeof(struct htab_elem) +
			  round_up(htab->map.key_size, 8);

	htab->elem_size += round_up(htab->map.value_size, 8);

	err = -E2BIG;
	/* prevent zero size kmalloc and check for u32 overflow */
	if (htab->n_buckets == 0 ||
	    htab->n_buckets > U32_MAX / sizeof(struct bucket))
		goto free_htab;

	cost = (u64) htab->n_buckets * sizeof(struct bucket) +
	       (u64) htab->elem_size * htab->map.max_entries;

	cost += (u64) htab->elem_size;

	err = -ENOMEM;
	htab->buckets = (struct bucket*)malloc(htab->n_buckets *
					   sizeof(struct bucket));
	if (!htab->buckets)
		goto free_htab;

	htab->hashrnd = 0; // TODO

	for (i = 0; i < htab->n_buckets; i++) {
		htab->buckets[i].head.first = NULL;
		pthread_mutex_init(&htab->buckets[i].lock, NULL);
	}

	if (prealloc) {
		err = prealloc_init(htab);
		if (err)
			goto free_buckets;

		err = alloc_extra_elems(htab);
		if (err)
			goto free_prealloc;
	}

	return &htab->map;

free_prealloc:
	prealloc_destroy(htab);
free_buckets:
	free(htab->buckets);
free_htab:
	free(htab);
	return NULL;
}

static inline u32 htab_map_hash(const void *key, u32 key_len, u32 hashrnd)
{
	return jhash(key, key_len, hashrnd);
}

static inline struct bucket *__select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &htab->buckets[hash & (htab->n_buckets - 1)];
}

static inline struct hlist_nulls_head *select_bucket(struct bpf_htab *htab, u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

/* this lookup function can only be called with bucket lock taken */
static struct htab_elem *lookup_elem_raw(struct hlist_nulls_head *head, u32 hash,
					 void *key, u32 key_size)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;
	
	if (head == NULL) return NULL;

	n = head->first;
	
	while (n) {
		l = container_of(n, struct htab_elem, hash_node);
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;
		n = n->next;
	}

	return NULL;
}

/* can be called without bucket lock. it will repeat the loop in
 * the unlikely event when elements moved from one bucket into another
 * while link list is being walked
 */
static struct htab_elem *lookup_nulls_elem_raw(struct hlist_nulls_head *head,
					       u32 hash, void *key,
					       u32 key_size, u32 n_buckets)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

again:
	if (head == NULL) return NULL;

	n = head->first;
	
	while (n) {
		l = container_of(n, struct htab_elem, hash_node);
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;
		n = n->next;
	}

	// TODO: not understand
	if (get_nulls_value(n) != (hash & (n_buckets - 1)))
		goto again;

	return NULL;
}

/* Called from syscall or from eBPF program directly, so
 * arguments have to match bpf_map_lookup_elem() exactly.
 * The return value is adjusted by BPF instructions
 * in htab_map_gen_lookup().
 */
static void *__htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	head = select_bucket(htab, hash);

	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	return l;
}

static void *htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct htab_elem *l = __htab_map_lookup_elem(map, key);

	if (l)
		return l->key + round_up(map->key_size, 8);

	return NULL;
}


/* Called from syscall */
static int htab_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct htab_elem *l, *next_l;
	struct hlist_nulls_node *nn;
	u32 hash, key_size;
	int i = 0;

	key_size = map->key_size;

	if (!key)
		goto find_first_elem;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	head = select_bucket(htab, hash);

	/* lookup the key */
	l = lookup_nulls_elem_raw(head, hash, key, key_size, htab->n_buckets);

	if (!l)
		goto find_first_elem;

	/* key was found, get next key in the same bucket */
	nn = &l->hash_node;

	if (nn = NULL) goto find_first_elem;
	nn = nn->next;
	if (nn = NULL) goto find_first_elem;
	next_l = container_of(nn, struct htab_elem, hash_node);

	if (next_l) {
		/* if next elem in this hash list is non-zero, just return it */
		memcpy(next_key, next_l->key, key_size);
		return 0;
	}

	/* no more elements in this hash list, go to the next bucket */
	i = hash & (htab->n_buckets - 1);
	i++;

find_first_elem:
	/* iterate over buckets */
	for (; i < htab->n_buckets; i++) {
		head = select_bucket(htab, i);

		if (head->first == NULL) continue;
		/* pick first element in the bucket */
		next_l = container_of(head->first, struct htab_elem, hash_node);
		if (next_l) {
			/* if it's not empty, just return it */
			memcpy(next_key, next_l->key, key_size);
			return 0;
		}
	}

	/* iterated over all buckets and all elements */
	return -1;
}

static void htab_elem_free(struct bpf_htab *htab, struct htab_elem *l)
{
	free(l);
}


static void free_htab_elem(struct bpf_htab *htab, struct htab_elem *l)
{
	struct bpf_map *map = &htab->map;

	if (htab_is_prealloc(htab)) {
		freelist_push(htab->freelist.freelist, &l->fnode);
	} else {
		atomic_dec_count(htab);
		l->htab = htab;
		htab_elem_free(htab, l);
	}
}


static struct htab_elem *alloc_htab_elem(struct bpf_htab *htab, void *key,
					 void *value, u32 key_size, u32 hash,
					 bool percpu, bool onallcpus,
					 struct htab_elem *old_elem)
{
	u32 size = htab->map.value_size;
	bool prealloc = htab_is_prealloc(htab);
	struct htab_elem *l_new, **pl_new;

	if (prealloc) {
		if (old_elem) {
			/* if we're updating the existing element,
			 * use per-cpu extra elems to avoid freelist_pop/push
			 */
			pl_new = &htab->extra_elems;
			l_new = *pl_new;
			*pl_new = old_elem;
		} else {
			struct freelist_node *l;

			l = freelist_pop(&htab->freelist);
			if (!l)
				return NULL;
			l_new = container_of(l, struct htab_elem, fnode);
		}
	} else {
		if (atomic_inc_count_return(htab) > htab->map.max_entries)
			if (!old_elem) {
				/* when map is full and update() is replacing
				 * old element, it's ok to allocate, since
				 * old element will be freed immediately.
				 * Otherwise return an error
				 */
				l_new = NULL;
				goto dec_count;
			}
		l_new = (struct htab_elem*)malloc(htab->elem_size);
		if (!l_new) {
			l_new = NULL;
			goto dec_count;
		}
	}

	memcpy(l_new->key, key, key_size);

	memcpy(l_new->key + round_up(key_size, 8), value, htab->map.value_size);

	l_new->hash = hash;
	return l_new;
dec_count:
	atomic_dec_count(htab);
	return l_new;
}

/* Called from syscall or from eBPF program */
static int htab_map_update_elem(struct bpf_map *map, void *key, void *value,
				u64 map_flags)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct htab_elem *l_new = NULL, *l_old;
	struct hlist_nulls_head *head;
	unsigned long flags;
	struct bucket *b;
	u32 key_size, hash;
	int ret;

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);

	b = __select_bucket(htab, hash);
	head = &b->head;

	/* bpf_map_update_elem() can be called in_irq() */
	pthread_mutex_lock(&b->lock);

	l_old = lookup_elem_raw(head, hash, key, key_size);

	l_new = alloc_htab_elem(htab, key, value, key_size, hash, false, false,
				l_old);
	if (l_new == NULL) {
		/* all pre-allocated elements are in use or memory exhausted */
		ret = -1;
		goto err;
	}

	/* add new element to the head of the list, so that
	 * concurrent search will find it before old elem
	 */
	hlist_nulls_add_head(&l_new->hash_node, head);
	if (l_old) {
		hlist_nulls_del(&l_old->hash_node);
		if (!htab_is_prealloc(htab))
			free_htab_elem(htab, l_old);
	}
	ret = 0;
err:
	pthread_mutex_unlock(&b->lock);
	return ret;
}



/* Called from syscall or from eBPF program */
static int htab_map_delete_elem(struct bpf_map *map, void *key)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	struct hlist_nulls_head *head;
	struct bucket *b;
	struct htab_elem *l;
	unsigned long flags;
	u32 hash, key_size;
	int ret = -1;

	key_size = map->key_size;

	hash = htab_map_hash(key, key_size, htab->hashrnd);
	b = __select_bucket(htab, hash);
	head = &b->head;

	pthread_mutex_lock(&b->lock);

	l = lookup_elem_raw(head, hash, key, key_size);

	if (l) {
		hlist_nulls_del(&l->hash_node);
		free_htab_elem(htab, l);
		ret = 0;
	}

	pthread_mutex_unlock(&b->lock);
	return ret;
}


static void delete_all_elements(struct bpf_htab *htab)
{
	int i;

	for (i = 0; i < htab->n_buckets; i++) {
		struct bucket *b = __select_bucket(htab, i);
		struct hlist_nulls_head *head = select_bucket(htab, i);
		struct hlist_nulls_node *n;
		struct htab_elem *l;
		pthread_mutex_lock(&b->lock);

		if (head == NULL) continue;
		n = head->first;
		while (n != NULL) {
			l = container_of(n, struct htab_elem, hash_node);
			n = n->next;
			hlist_nulls_del(&l->hash_node);
			htab_elem_free(htab, l);
		}

		pthread_mutex_unlock(&b->lock);
	}
}

/* Called when map->refcnt goes to zero, either from workqueue or from syscall */
static void htab_map_free(struct bpf_map *map)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);

	if (!htab_is_prealloc(htab))
		delete_all_elements(htab);
	else
		prealloc_destroy(htab);

	free(htab->buckets);
	free(htab);
}


const struct bpf_map_ops htab_map_ops = {
	.map_alloc_check = htab_map_alloc_check,
	.map_alloc = htab_map_alloc,
	.map_free = htab_map_free,
	.map_get_next_key = htab_map_get_next_key,
	.map_lookup_elem = htab_map_lookup_elem,
	.map_update_elem = htab_map_update_elem,
	.map_delete_elem = htab_map_delete_elem,
};


// Code added by CBackyx

int freelist_init(struct freelist * s) {
	s->freelist = (struct freelist_head*)malloc(sizeof(*s->freelist));
	pthread_mutex_init(&(s->freelist->lock), NULL);
}

void freelist_populate(struct freelist *s, void *buf, u32 elem_size,
			    u32 nr_elems)
{
	struct freelist_head *head;
	unsigned long flags;
	int i, nr_entries;

	nr_entries = nr_elems; // TODO need to add 1?
	i = 0;

	/* disable irq to workaround lockdep false positive
	 * in bpf usage pcpu_freelist_populate() will never race
	 * with pcpu_freelist_push()
	 */
	// TODO: disable the interrupt
again:
	head = s->freelist;
	freelist_push(head, (struct freelist_node*)buf);
	i++;
	buf += elem_size;
	if (i < nr_entries)
		goto again;
}

void freelist_push(struct freelist_head *head,
					 struct freelist_node *node)
{
	pthread_mutex_lock(&head->lock);
	node->next = head->first;
	head->first = node;
	pthread_mutex_unlock(&head->lock);
}

void freelist_destroy(struct freelist *s)
{
	free(s->freelist);
}

struct freelist_node *freelist_pop(struct freelist *s)
{
	// TODO: disable interrupt

	struct freelist_head *head;
	struct freelist_node *node;

	head = s->freelist;
	pthread_mutex_lock(&head->lock);
	node = head->first;
	if (node) {
		head->first = node->next;
		pthread_mutex_unlock(&head->lock);
		return node;
	}
	else return NULL;
}

void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr)
{
	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->map_flags;
}

void atomic_dec_count(struct bpf_htab *htab) {
	pthread_mutex_lock(&htab->count_lock);
	htab->count--;
	pthread_mutex_unlock(&htab->count_lock);
}

void atomic_inc_count(struct bpf_htab *htab) {
	pthread_mutex_lock(&htab->count_lock);
	htab->count++;
	pthread_mutex_unlock(&htab->count_lock);
}

u32 atomic_inc_count_return(struct bpf_htab *htab) {
	pthread_mutex_lock(&htab->count_lock);
	htab->count++;
	pthread_mutex_unlock(&htab->count_lock);
	return htab->count;
}

void hlist_nulls_add_head(struct hlist_nulls_node *n,
					struct hlist_nulls_head *h)
{
	struct hlist_nulls_node *first = h->first;

	n->next = first;
	n->pprev = &h->first;
	h->first = n;
	if (first != NULL)
		first->pprev = &n->next;
}

void hlist_nulls_del(struct hlist_nulls_node *n)
{
	struct hlist_nulls_node *next = n->next;
	struct hlist_nulls_node **pprev = n->pprev;

	*pprev = next;
	if (next != NULL)
		next->pprev = pprev;

	n->pprev = NULL;
}