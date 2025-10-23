// tiny_mmap_alloc.c (Linux/macOS; a macOS no hi ha mremap)
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

typedef struct block {
	size_t size; // mida útil del bloc
	int free; // 1 si lliure
	struct block *next; // llista en la mateixa arena
	struct block *prev;
} block_t;

typedef struct arena {
	size_t size; // mida total de l'arena (sense header)
	struct arena *next;
	block_t *first; // primer bloc dins l'arena
} arena_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static arena_t *g_arenas = NULL;

static size_t align_up(size_t n, size_t a) {
	return (n + (a - 1)) & ~ (a - 1);
}
static size_t pagesz(void) {
	static size_t p;
	if (!p) {
		p = getpagesize ();
	}
	return p;
}

static arena_t *new_arena(size_t want) {
	size_t base = align_up (want + sizeof (arena_t) + sizeof (block_t), pagesz ());
	void *mem = mmap (NULL, base, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		return NULL;
	}
	arena_t *A = (arena_t *)mem;
	A->size = base - sizeof (arena_t);
	A->next = NULL;
	block_t *B = (block_t *) ((char *)mem + sizeof (arena_t));
	B->size = A->size - sizeof (block_t);
	B->free = 1;
	B->next = NULL;
	B->prev = NULL;
	A->first = B;
	return A;
}

static void split_block(block_t *b, size_t need) {
	size_t asz = align_up (need, 16);
	if (b->size >= asz + sizeof (block_t) + 32) {
		block_t *n = (block_t *) ((char *)b + sizeof (block_t) + asz);
		n->size = b->size - asz - sizeof (block_t);
		n->free = 1;
		n->next = b->next;
		n->prev = b;
		if (n->next) {
			n->next->prev = n;
		}
		b->next = n;
		b->size = asz;
	}
	b->free = 0;
}

static void coalesce(block_t *b) {
	// uneix amb next
	if (b->next && b->next->free) {
		b->size += sizeof (block_t) + b->next->size;
		b->next = b->next->next;
		if (b->next) {
			b->next->prev = b;
		}
	}
	// uneix amb prev
	if (b->prev && b->prev->free) {
		b = b->prev;
		b->size += sizeof (block_t) + b->next->size;
		b->next = b->next->next;
		if (b->next) {
			b->next->prev = b;
		}
	}
}

static void *big_alloc(size_t sz) {
	size_t req = align_up (sz, pagesz ());
	void *p = mmap (NULL, req + sizeof (block_t), PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		return NULL;
	}
	block_t *b = (block_t *)p;
	b->size = req;
	b->free = 0;
	b->next = b->prev = NULL;
	// retornem la zona útil
	return (char *)p + sizeof (block_t);
}

static void big_free(void *ptr) {
	if (!ptr) {
		return;
	}
	block_t *b = (block_t *) ((char *)ptr - sizeof (block_t));
	munmap ((void *)b, b->size + sizeof (block_t));
}

static void *find_fit(size_t sz) {
	for (arena_t *A = g_arenas; A; A = A->next) {
		for (block_t *b = A->first; b; b = b->next) {
			if (b->free && b->size >= sz) {
				split_block (b, sz);
				return (char *)b + sizeof (block_t);
			}
		}
	}
	return NULL;
}

void *my_malloc(size_t sz) {
	if (!sz) {
		return NULL;
	}
	pthread_mutex_lock (&g_lock);
	// grans blocs directes per mmaps per evitar fragmentació
	if (sz >= 128 * 1024) {
		pthread_mutex_unlock (&g_lock);
		return big_alloc (sz);
	}
	void *p = find_fit (sz);
	if (!p) {
		size_t arena_sz = (sz < 1 << 20)? (1 << 20): align_up (sz, pagesz ()) * 2;
		arena_t *A = new_arena (arena_sz);
		if (!A) {
			pthread_mutex_unlock (&g_lock);
			return NULL;
		}
		A->next = g_arenas;
		g_arenas = A;
		p = find_fit (sz);
	}
	pthread_mutex_unlock (&g_lock);
	return p;
}

void my_free(void *ptr) {
	if (!ptr) {
		return;
	}
	block_t *b = (block_t *) ((char *)ptr - sizeof (block_t));
	// Heurística: si sembla “big” (map independent), munmap
	if (b->next == NULL && b->prev == NULL && (b->size % pagesz ()) == 0) {
		// Això no és perfecte, però ens serveix de demo
		big_free (ptr);
		return;
	}
	pthread_mutex_lock (&g_lock);
	b->free = 1;
	coalesce (b);
	pthread_mutex_unlock (&g_lock);
}

void *my_realloc(void *ptr, size_t ns) {
	if (!ptr) {
		return my_malloc (ns);
	}
	if (!ns) {
		my_free (ptr);
		return NULL;
	}
#ifdef __linux__
	// Intent de “realloc” eficient per blocs grans independents
	block_t *b = (block_t *) ((char *)ptr - sizeof (block_t));
	if (b->next == NULL && b->prev == NULL) {
		size_t old = b->size + sizeof (block_t);
		size_t want = align_up (ns, pagesz ()) + sizeof (block_t);
		void *np = mremap ((void *)b, old, want, /*may move*/ 1 /*MREMAP_MAYMOVE*/);
		if (np != MAP_FAILED) {
			block_t *nb = (block_t *)np;
			nb->size = want - sizeof (block_t);
			nb->free = 0;
			return (char *)np + sizeof (block_t);
		}
	}
#endif
	// Fallback portable
	void *q = my_malloc (ns);
	if (!q) {
		return NULL;
	}
	block_t *b = (block_t *) ((char *)ptr - sizeof (block_t));
	size_t copy = (ns < b->size)? ns: b->size;
	memcpy (q, ptr, copy);
	my_free (ptr);
	return q;
}
