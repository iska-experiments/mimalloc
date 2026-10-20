#include "static.c"
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#define check(c) do { if (!(c)) { fprintf(stderr, "check failed: %s\n", #c); abort(); } } while (0)
typedef struct { unsigned char *p; size_t size, alignment; unsigned char value; } Slot;
typedef struct { uint64_t seed; unsigned char *cross; } Worker;

static uint64_t next(uint64_t *state) {
  *state ^= *state << 13; *state ^= *state >> 7; *state ^= *state << 17;
  return *state;
}

static void verify(Slot s) {
  if (!s.p) return;
  check((uintptr_t)s.p % s.alignment == 0);
  for (size_t j = 0; j < s.size; j++) check(s.p[j] == s.value);
}

static void *worker(void *arg) {
  Worker *w = arg;
  for (size_t i = 0; i < 4096; i++) check(w->cross[i] == (unsigned char)w->seed);
  mi_free(w->cross);
  Slot slots[32] = {0};
  for (unsigned i = 0; i < 4096; i++) {
    Slot *s = &slots[next(&w->seed) % 32];
    verify(*s);
    size_t size = 1 + next(&w->seed) % 65536;
    if (s->p && (next(&w->seed) & 1)) {
      unsigned char *p = mi_realloc_aligned(s->p, size, s->alignment);
      check(p != NULL);
      Slot prefix = {p, (size < s->size ? size : s->size), s->alignment, s->value};
      verify(prefix);
      s->p = p; s->size = size;
    } else {
      mi_free(s->p);
      s->alignment = (size_t)1 << (4 + next(&w->seed) % 13);
      s->size = size;
      s->p = mi_zalloc_aligned(size, s->alignment);
      s->value = 0;
      check(s->p != NULL);
      verify(*s);
    }
    s->value = (unsigned char)next(&w->seed);
    memset(s->p, s->value, s->size);
  }
  for (unsigned i = 0; i < 32; i++) { verify(slots[i]); mi_free(slots[i].p); }
  return NULL;
}

static void policy(uintptr_t address, bool metadata) {
  FILE *maps = fopen("/proc/self/smaps", "r"); check(maps != NULL);
  char line[1024]; bool selected = false, found = false;
  while (fgets(line, sizeof(line), maps)) {
    unsigned long long lo, hi;
    if (sscanf(line, "%llx-%llx", &lo, &hi) == 2) selected = lo <= address && address < hi;
    if (selected && strncmp(line, "VmFlags:", 8) == 0) {
      bool small = strstr(line, " nh") != NULL, huge = strstr(line, " hg") != NULL;
      check(metadata ? (small && !huge) : (huge && !small)); found = true; break;
    }
  }
  fclose(maps); check(found);
}

int main(int argc, char **argv) {
  unsigned char *data = mi_malloc(64);
  check(data != NULL);
  memset(data, 0x39, 64);
  mi_page_t *page = _mi_ptr_page(data);
  check(mi_page_is_in_arena(page));
  mi_arena_t *arena = page->memid.mem.arena.arena;
  uintptr_t info_end = (uintptr_t)arena + mi_size_of_slices(arena->info_slices);
#if defined(MI_NO_THP)
  const bool isolated = false;
#else
  const bool isolated = (MI_SECURE == 0 && arena->memid.initially_committed && _mi_os_large_page_size() > MI_ARENA_SLICE_SIZE &&
                         mi_option_is_enabled(mi_option_allow_thp) && !arena->memid.is_pinned);
#endif
  if (isolated) check(info_end % _mi_os_large_page_size() == 0);
  else check(arena->info_slices == mi_arena_info_slices_needed(arena->slice_count, NULL));
  check((uintptr_t)data >= info_end);
  if (isolated) { policy((uintptr_t)arena, true); policy((uintptr_t)data, false); }
  pthread_t threads[8]; Worker workers[8];
  for (unsigned i = 0; i < 8; i++) {
    workers[i].seed = 0x18438 + i;
    workers[i].cross = mi_malloc(4096); check(workers[i].cross != NULL);
    memset(workers[i].cross, (unsigned char)workers[i].seed, 4096);
    check(pthread_create(&threads[i], NULL, worker, &workers[i]) == 0);
  }
  for (unsigned i = 0; i < 8; i++) check(pthread_join(threads[i], NULL) == 0);
  size_t bytes = 64 * MI_MiB;
  void *external = mmap(NULL, bytes + MI_ARENA_SLICE_SIZE, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  check(external != MAP_FAILED);
  void *aligned = _mi_align_up_ptr(external, MI_ARENA_SLICE_SIZE);
  mi_arena_id_t id;
  check(mi_manage_os_memory_ex(aligned, bytes, true, false, true, -1, true, &id));
  mi_arena_t *ext = _mi_arena_from_id(id);
  check(ext->info_slices == mi_arena_info_slices_needed(ext->slice_count, NULL));
  mi_heap_t *heap = mi_heap_new_in_arena(id); check(heap != NULL);
  void *value = mi_heap_malloc(heap, 65536); check(value != NULL);
  memset(value, 0x9a, 65536); mi_free(value); mi_heap_delete(heap);
  mi_arena_id_t plain_id;
  check(mi_reserve_os_memory_ex(64 * MI_MiB, true, false, true, &plain_id) == 0);
  mi_arena_t *plain = _mi_arena_from_id(plain_id);
  check(plain->info_slices == mi_arena_info_slices_needed(plain->slice_count, NULL));
  printf("{\"pid\":%d,\"arena\":%llu,\"info_end\":%llu,\"data\":%llu,"
         "\"operations\":32768,\"cross_thread_frees\":8,\"external_excluded\":true}\n",
         getpid(), (unsigned long long)(uintptr_t)arena,
         (unsigned long long)info_end, (unsigned long long)(uintptr_t)data);
  fflush(stdout);
  if (argc > 1 && strcmp(argv[1], "--inspect") == 0) check(getchar() == '\n');
  mi_free(data);
}
