#include "../globals/global_types.h"

#include "ideal_fusion.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../general.param.h"
#include "../map.h"
#include "../memory/memory.param.h"
#include "../op.h"
#include "../statistics.h"

/*
 * Pass 1 keeps recently fetched loads grouped by data-cache block. When a
 * later load arrives, the matching step can inspect only earlier loads from
 * the same block instead of scanning the full dynamic instruction history.
 */
#define IDEAL_FUSION_LOAD_CANDIDATE_BUCKETS 4096
#define IDEAL_FUSION_PAIR_INDEX_BUCKETS 1000003
#define IDEAL_FUSION_CSV_FIELDS 11
#define IDEAL_FUSION_CSV_LINE_SIZE 1024
#define IDEAL_FUSION_CSV_HEADER                                                   \
  "load1_pc,load1_data_addr,load1_block_offset,load1_mem_size,"                  \
  "load1_micro_op_num,load2_pc,load2_data_addr,load2_block_offset,"              \
  "load2_mem_size,load2_micro_op_num,micro_op_distance"

typedef struct Ideal_Fusion_Load_Candidate_struct {
  Addr pc;
  Addr virtual_addr;
  Addr cache_block_addr;
  Addr cache_block_offset;
  uns mem_size;
  Counter micro_op_num;
  Flag fused;
  struct Ideal_Fusion_Load_Candidate_struct* next;
} Ideal_Fusion_Load_Candidate;

typedef struct Ideal_Fusion_Pair_struct {
  Counter load1_micro_op_num;
  Counter load2_micro_op_num;
  Addr load1_pc;
  Addr load2_pc;
  Addr load1_data_addr;
  Addr load2_data_addr;
  Addr load1_block_offset;
  Addr load2_block_offset;
  uns load1_mem_size;
  uns load2_mem_size;
  struct Ideal_Fusion_Pair_struct* next;
} Ideal_Fusion_Pair;

typedef struct Ideal_Fusion_Readiness_struct {
  Counter load1_micro_op_num;
  Op* load2;
  Counter load2_unique_num;
  Flag load1_completed;
  struct Ideal_Fusion_Readiness_struct* next;
} Ideal_Fusion_Readiness;

/*
 * Candidate files identify dynamic ops using the order in which on-path ops
 * are fetched. Off-path ops do not advance this counter.
 */
static Counter next_on_path_micro_op_num = 0;

static Ideal_Fusion_Load_Candidate*
  load_candidates[IDEAL_FUSION_LOAD_CANDIDATE_BUCKETS] = {NULL};
static Counter last_load_cleanup_micro_op_num = 0;
static FILE* candidate_log = NULL;
static Counter logged_candidate_pair_count = 0;

/*
 * A fetched op knows only its own sequence number. Store each pair in two
 * indexes so pass 2 can quickly recognize both LOAD1 and LOAD2 without
 * scanning every pair.
 */
static Ideal_Fusion_Pair*
  load1_pair_index[IDEAL_FUSION_PAIR_INDEX_BUCKETS] = {NULL};
static Ideal_Fusion_Pair*
  load2_pair_index[IDEAL_FUSION_PAIR_INDEX_BUCKETS] = {NULL};
static Flag pair_indexes_loaded = FALSE;
static Ideal_Fusion_Readiness*
  readiness_index[IDEAL_FUSION_PAIR_INDEX_BUCKETS] = {NULL};

static Addr get_cache_block_addr(Addr addr) {
  return (addr / DCACHE_LINE_SIZE) * DCACHE_LINE_SIZE;
}

static uns get_candidate_bucket(Addr cache_block_addr) {
  uns64 key = cache_block_addr;
  key ^= key >> 33;
  key *= 0xff51afd7ed558ccdULL;
  key ^= key >> 33;
  return key % IDEAL_FUSION_LOAD_CANDIDATE_BUCKETS;
}

static uns get_pair_index_bucket(Counter micro_op_num) {
  uns64 key = micro_op_num;
  key ^= key >> 33;
  key *= 0xff51afd7ed558ccdULL;
  key ^= key >> 33;
  return key % IDEAL_FUSION_PAIR_INDEX_BUCKETS;
}

/*
 * Adds a precomputed LOAD1/LOAD2 relationship to both indexes so either
 * dynamic load can find its partner when it is fetched during pass 2.
 * These helpers are used by the pass-2 CSV loader and classifier added next.
 */
static void index_fusion_pair(const Ideal_Fusion_Pair* pair) {
  Ideal_Fusion_Pair* load1_index_entry;
  Ideal_Fusion_Pair* load2_index_entry;
  uns load1_bucket = get_pair_index_bucket(pair->load1_micro_op_num);
  uns load2_bucket = get_pair_index_bucket(pair->load2_micro_op_num);

  load1_index_entry = (Ideal_Fusion_Pair*)malloc(sizeof(*load1_index_entry));
  load2_index_entry = (Ideal_Fusion_Pair*)malloc(sizeof(*load2_index_entry));
  if (!load1_index_entry || !load2_index_entry) {
    free(load1_index_entry);
    free(load2_index_entry);
    fprintf(stderr, "Ideal fusion: could not allocate pass-2 pair indexes.\n");
    exit(EXIT_FAILURE);
  }

  *load1_index_entry = *pair;
  load1_index_entry->next = load1_pair_index[load1_bucket];
  load1_pair_index[load1_bucket] = load1_index_entry;

  *load2_index_entry = *pair;
  load2_index_entry->next = load2_pair_index[load2_bucket];
  load2_pair_index[load2_bucket] = load2_index_entry;
}

/* Returns the fusion pair when this dynamic op is a precomputed LOAD1. */
static Ideal_Fusion_Pair* lookup_load1_pair(Counter micro_op_num) {
  Ideal_Fusion_Pair* pair;
  uns bucket = get_pair_index_bucket(micro_op_num);

  for (pair = load1_pair_index[bucket]; pair; pair = pair->next) {
    if (pair->load1_micro_op_num == micro_op_num)
      return pair;
  }

  return NULL;
}

/* Returns the fusion pair when this dynamic op is a precomputed LOAD2. */
static Ideal_Fusion_Pair* lookup_load2_pair(Counter micro_op_num) {
  Ideal_Fusion_Pair* pair;
  uns bucket = get_pair_index_bucket(micro_op_num);

  for (pair = load2_pair_index[bucket]; pair; pair = pair->next) {
    if (pair->load2_micro_op_num == micro_op_num)
      return pair;
  }

  return NULL;
}

static Ideal_Fusion_Readiness* lookup_readiness(Counter load1_micro_op_num) {
  Ideal_Fusion_Readiness* readiness;
  uns bucket = get_pair_index_bucket(load1_micro_op_num);

  for (readiness = readiness_index[bucket]; readiness;
       readiness = readiness->next) {
    if (readiness->load1_micro_op_num == load1_micro_op_num)
      return readiness;
  }

  return NULL;
}

static Ideal_Fusion_Readiness* get_or_create_readiness(
  Counter load1_micro_op_num) {
  Ideal_Fusion_Readiness* readiness = lookup_readiness(load1_micro_op_num);
  uns bucket;

  if (readiness)
    return readiness;

  readiness = (Ideal_Fusion_Readiness*)calloc(1, sizeof(*readiness));
  if (!readiness) {
    fprintf(stderr, "Ideal fusion: could not allocate LOAD2 readiness entry.\n");
    exit(EXIT_FAILURE);
  }

  readiness->load1_micro_op_num = load1_micro_op_num;
  bucket = get_pair_index_bucket(load1_micro_op_num);
  readiness->next = readiness_index[bucket];
  readiness_index[bucket] = readiness;
  return readiness;
}

static void remove_readiness(Ideal_Fusion_Readiness* readiness) {
  Ideal_Fusion_Readiness** entry;
  uns bucket = get_pair_index_bucket(readiness->load1_micro_op_num);

  for (entry = &readiness_index[bucket]; *entry; entry = &(*entry)->next) {
    if (*entry == readiness) {
      *entry = readiness->next;
      free(readiness);
      return;
    }
  }
}

/*
 * Pass 2 only tags the fetched load in this step. Later pipeline changes will
 * use the role and partner number to model the fused LOAD1 and LOAD2 behavior.
 */
static void classify_load(Op* op) {
  Ideal_Fusion_Pair* pair;

  if (op->inst_info->table_info.mem_type != MEM_LD ||
      op->oracle_info.va == 0 || op->oracle_info.mem_size == 0)
    return;

  pair = lookup_load1_pair(op->ideal_fusion_micro_op_num);
  if (pair) {
    op->ideal_fusion_load_role = IDEAL_FUSION_LOAD1;
    op->ideal_fusion_partner_micro_op_num = pair->load2_micro_op_num;
    STAT_EVENT(op->proc_id, IDEAL_FUSION_LOAD1_TAGGED);
    return;
  }

  pair = lookup_load2_pair(op->ideal_fusion_micro_op_num);
  if (pair) {
    op->ideal_fusion_load_role = IDEAL_FUSION_LOAD2;
    op->ideal_fusion_partner_micro_op_num = pair->load1_micro_op_num;
    STAT_EVENT(op->proc_id, IDEAL_FUSION_LOAD2_TAGGED);
  }
}

static Flag access_fits_in_cache_block(Addr addr, uns mem_size) {
  Addr cache_block_addr;

  if (mem_size == 0)
    return FALSE;

  cache_block_addr = get_cache_block_addr(addr);
  return addr + mem_size - 1 < cache_block_addr + DCACHE_LINE_SIZE;
}

static void pair_log_error(Counter line_num, const char* message) {
  fprintf(stderr, "Ideal fusion: invalid candidate log '%s' at line %llu: %s\n",
          IDEAL_FUSION_LOG, line_num, message);
  exit(EXIT_FAILURE);
}

static Flag parse_csv_number(const char* text, uns64* value) {
  char* end;

  if (!text || !text[0])
    return FALSE;

  errno = 0;
  *value = strtoull(text, &end, 0);
  return errno == 0 && end != text && *end == '\0';
}

/*
 * Pass 2 reads the complete metadata recorded by pass 1. Keeping addresses,
 * offsets, and sizes alongside sequence numbers makes later LOAD1 modeling
 * explicit and keeps the candidate log useful for debugging.
 */
static void load_pair_indexes(void) {
  FILE* pair_log;
  char line[IDEAL_FUSION_CSV_LINE_SIZE];
  Counter line_num = 0;

  if (pair_indexes_loaded)
    return;

  if (!IDEAL_FUSION_LOG || !IDEAL_FUSION_LOG[0]) {
    fprintf(stderr, "Ideal fusion: candidate log path must not be empty.\n");
    exit(EXIT_FAILURE);
  }

  pair_log = fopen(IDEAL_FUSION_LOG, "r");
  if (!pair_log) {
    fprintf(stderr, "Ideal fusion: could not open candidate log '%s': %s\n",
            IDEAL_FUSION_LOG, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (!fgets(line, sizeof(line), pair_log)) {
    fclose(pair_log);
    pair_log_error(1, "missing CSV header");
  }
  line_num++;
  line[strcspn(line, "\r\n")] = '\0';
  if (strcmp(line, IDEAL_FUSION_CSV_HEADER) != 0) {
    fclose(pair_log);
    pair_log_error(line_num, "unexpected CSV header");
  }

  while (fgets(line, sizeof(line), pair_log)) {
    Ideal_Fusion_Pair pair = {0};
    char* fields[IDEAL_FUSION_CSV_FIELDS];
    char* saveptr = NULL;
    char* field;
    uns64 values[IDEAL_FUSION_CSV_FIELDS];
    uns field_count = 0;
    Counter recorded_distance;

    line_num++;
    line[strcspn(line, "\r\n")] = '\0';
    if (!line[0])
      continue;

    for (field = strtok_r(line, ",", &saveptr); field;
         field = strtok_r(NULL, ",", &saveptr)) {
      if (field_count == IDEAL_FUSION_CSV_FIELDS) {
        fclose(pair_log);
        pair_log_error(line_num, "too many CSV fields");
      }
      fields[field_count++] = field;
    }

    if (field_count != IDEAL_FUSION_CSV_FIELDS) {
      fclose(pair_log);
      pair_log_error(line_num, "wrong number of CSV fields");
    }

    for (field_count = 0; field_count < IDEAL_FUSION_CSV_FIELDS;
         field_count++) {
      if (!parse_csv_number(fields[field_count], &values[field_count])) {
        fclose(pair_log);
        pair_log_error(line_num, "invalid numeric field");
      }
    }

    if (values[3] > UINT_MAX || values[8] > UINT_MAX) {
      fclose(pair_log);
      pair_log_error(line_num, "memory size is out of range");
    }

    pair.load1_pc = values[0];
    pair.load1_data_addr = values[1];
    pair.load1_block_offset = values[2];
    pair.load1_mem_size = values[3];
    pair.load1_micro_op_num = values[4];
    pair.load2_pc = values[5];
    pair.load2_data_addr = values[6];
    pair.load2_block_offset = values[7];
    pair.load2_mem_size = values[8];
    pair.load2_micro_op_num = values[9];
    recorded_distance = values[10];

    if (pair.load1_micro_op_num == 0 ||
        pair.load2_micro_op_num <= pair.load1_micro_op_num ||
        pair.load2_micro_op_num - pair.load1_micro_op_num !=
          recorded_distance) {
      fclose(pair_log);
      pair_log_error(line_num, "invalid micro-op sequence numbers");
    }

    if (get_cache_block_addr(pair.load1_data_addr) !=
          get_cache_block_addr(pair.load2_data_addr) ||
        pair.load1_block_offset !=
          pair.load1_data_addr - get_cache_block_addr(pair.load1_data_addr) ||
        pair.load2_block_offset !=
          pair.load2_data_addr - get_cache_block_addr(pair.load2_data_addr) ||
        !access_fits_in_cache_block(pair.load1_data_addr,
                                    pair.load1_mem_size) ||
        !access_fits_in_cache_block(pair.load2_data_addr,
                                    pair.load2_mem_size)) {
      fclose(pair_log);
      pair_log_error(line_num, "inconsistent cache-block metadata");
    }

    index_fusion_pair(&pair);
  }

  if (ferror(pair_log)) {
    fclose(pair_log);
    fprintf(stderr, "Ideal fusion: could not read candidate log '%s': %s\n",
            IDEAL_FUSION_LOG, strerror(errno));
    exit(EXIT_FAILURE);
  }

  if (fclose(pair_log) != 0) {
    fprintf(stderr, "Ideal fusion: could not close candidate log '%s': %s\n",
            IDEAL_FUSION_LOG, strerror(errno));
    exit(EXIT_FAILURE);
  }

  pair_indexes_loaded = TRUE;
}

static void candidate_log_error(const char* action) {
  fprintf(stderr, "Ideal fusion: could not %s candidate output file '%s': %s\n",
          action, IDEAL_FUSION_LOG, strerror(errno));
  exit(EXIT_FAILURE);
}

static void close_candidate_log(void) {
  if (!candidate_log)
    return;

  if (fflush(candidate_log) != 0)
    fprintf(stderr, "Ideal fusion: could not flush candidate output file '%s': %s\n",
            IDEAL_FUSION_LOG, strerror(errno));
  if (fclose(candidate_log) != 0)
    fprintf(stderr, "Ideal fusion: could not close candidate output file '%s': %s\n",
            IDEAL_FUSION_LOG, strerror(errno));
  candidate_log = NULL;
}

static void open_candidate_log(void) {
  if (candidate_log)
    return;

  if (!IDEAL_FUSION_LOG || !IDEAL_FUSION_LOG[0]) {
    fprintf(stderr, "Ideal fusion: candidate output path must not be empty.\n");
    exit(EXIT_FAILURE);
  }

  candidate_log = fopen(IDEAL_FUSION_LOG, "w");
  if (!candidate_log)
    candidate_log_error("open");

  if (fprintf(candidate_log, "%s\n", IDEAL_FUSION_CSV_HEADER) < 0 ||
      fflush(candidate_log) != 0)
    candidate_log_error("initialize");
  atexit(close_candidate_log);
}

static void log_matched_pair(Ideal_Fusion_Load_Candidate* load1, Op* load2) {
  Counter distance = load2->ideal_fusion_micro_op_num - load1->micro_op_num;
  Addr load2_block_addr = get_cache_block_addr(load2->oracle_info.va);

  open_candidate_log();
  if (fprintf(candidate_log,
              "0x%llx,0x%llx,%llu,%u,%llu,0x%llx,0x%llx,%llu,%u,%llu,%llu\n",
              load1->pc, load1->virtual_addr, load1->cache_block_offset,
              load1->mem_size, load1->micro_op_num, load2->inst_info->addr,
              load2->oracle_info.va, load2->oracle_info.va - load2_block_addr,
              load2->oracle_info.mem_size, load2->ideal_fusion_micro_op_num,
              distance) < 0)
    candidate_log_error("write to");

  if (++logged_candidate_pair_count % 1000 == 0 &&
      fflush(candidate_log) != 0)
    candidate_log_error("flush");
}

static Ideal_Fusion_Load_Candidate* find_matching_load1(Op* load2) {
  Ideal_Fusion_Load_Candidate* load1;
  Addr cache_block_addr;
  uns bucket;

  if (load2->inst_info->table_info.mem_type != MEM_LD ||
      load2->inst_info->table_info.num_dest_regs == 0 ||
      load2->oracle_info.va == 0 || load2->oracle_info.mem_size == 0)
    return NULL;

  cache_block_addr = get_cache_block_addr(load2->oracle_info.va);
  bucket = get_candidate_bucket(cache_block_addr);

  for (load1 = load_candidates[bucket]; load1; load1 = load1->next) {
    if (load1->cache_block_addr == cache_block_addr &&
        !load1->fused &&
        access_fits_in_cache_block(load1->virtual_addr, load1->mem_size) &&
        access_fits_in_cache_block(load2->oracle_info.va,
                                   load2->oracle_info.mem_size) &&
        load2->ideal_fusion_micro_op_num - load1->micro_op_num <
          IDEAL_FUSION_DISTANCE)
      return load1;
  }

  return NULL;
}

static void track_load(Op* op) {
  Ideal_Fusion_Load_Candidate* candidate;
  uns bucket;

  if (op->inst_info->table_info.mem_type != MEM_LD ||
      op->inst_info->table_info.num_dest_regs == 0 ||
      op->oracle_info.va == 0 || op->oracle_info.mem_size == 0)
    return;

  candidate = (Ideal_Fusion_Load_Candidate*)malloc(sizeof(*candidate));
  if (!candidate)
    return;

  candidate->pc = op->inst_info->addr;
  candidate->virtual_addr = op->oracle_info.va;
  candidate->cache_block_addr = get_cache_block_addr(op->oracle_info.va);
  candidate->cache_block_offset =
    op->oracle_info.va - candidate->cache_block_addr;
  candidate->mem_size = op->oracle_info.mem_size;
  candidate->micro_op_num = op->ideal_fusion_micro_op_num;
  candidate->fused = FALSE;

  bucket = get_candidate_bucket(candidate->cache_block_addr);
  candidate->next = load_candidates[bucket];
  load_candidates[bucket] = candidate;
}

/*
 * A store between LOAD1 and LOAD2 to the same cache block may change the data that LOAD2 observes.
 * Conservatively discard every earlier LOAD1 candidate from the store's cache
 * block, matching the original ideal-fusion implementation.
 */
static void invalidate_loads_for_store(Op* store) {
  Ideal_Fusion_Load_Candidate** candidate;
  Addr cache_block_addr;
  uns bucket;

  if (store->inst_info->table_info.mem_type != MEM_ST ||
      store->oracle_info.va == 0)
    return;

  cache_block_addr = get_cache_block_addr(store->oracle_info.va);
  bucket = get_candidate_bucket(cache_block_addr);
  candidate = &load_candidates[bucket];

  while (*candidate) {
    if ((*candidate)->cache_block_addr == cache_block_addr) {
      Ideal_Fusion_Load_Candidate* invalidated_candidate = *candidate;
      *candidate = invalidated_candidate->next;
      free(invalidated_candidate);
    } else {
      candidate = &(*candidate)->next;
    }
  }
}

static void cleanup_stale_loads(Counter current_micro_op_num) {
  uns bucket;

  for (bucket = 0; bucket < IDEAL_FUSION_LOAD_CANDIDATE_BUCKETS; bucket++) {
    Ideal_Fusion_Load_Candidate** candidate = &load_candidates[bucket];

    while (*candidate) {
      if ((*candidate)->fused ||
          current_micro_op_num - (*candidate)->micro_op_num >=
            IDEAL_FUSION_DISTANCE) {
        Ideal_Fusion_Load_Candidate* stale_candidate = *candidate;
        *candidate = stale_candidate->next;
        free(stale_candidate);
      } else {
        candidate = &(*candidate)->next;
      }
    }
  }
}

void ideal_fusion_on_fetch_op(Op* op) {
  if (!op || op->off_path)
    return;

  op->ideal_fusion_micro_op_num = ++next_on_path_micro_op_num;

  if (IDEAL_FUSION_PASS == 2) {
    load_pair_indexes();
    classify_load(op);
    return;
  }

  if (IDEAL_FUSION_PASS != 1 || IDEAL_FUSION_DISTANCE == 0)
    return;

  if (op->ideal_fusion_micro_op_num - last_load_cleanup_micro_op_num >=
      IDEAL_FUSION_DISTANCE) {
    cleanup_stale_loads(op->ideal_fusion_micro_op_num);
    last_load_cleanup_micro_op_num = op->ideal_fusion_micro_op_num;
  }

  if (op->inst_info->table_info.mem_type == MEM_ST) {
    invalidate_loads_for_store(op);
    return;
  }

  Ideal_Fusion_Load_Candidate* load1 = find_matching_load1(op);

  if (load1) {
    log_matched_pair(load1, op);
    load1->fused = TRUE;
  } else {
    track_load(op);
  }
}

Flag ideal_fusion_load2_is_nop(const Op* op) {
  return op && op->ideal_fusion_load_role == IDEAL_FUSION_LOAD2;
}

void ideal_fusion_on_rename(Op* op, void (*wake_action)(Op*, Op*, uns)) {
  Ideal_Fusion_Readiness* readiness;

  if (!op || op->off_path || IDEAL_FUSION_PASS != 2)
    return;

  if (op->ideal_fusion_load_role == IDEAL_FUSION_LOAD1) {
    get_or_create_readiness(op->ideal_fusion_micro_op_num);
    return;
  }

  if (!ideal_fusion_load2_is_nop(op))
    return;

  readiness = get_or_create_readiness(
    op->ideal_fusion_partner_micro_op_num);
  readiness->load2 = op;
  readiness->load2_unique_num = op->unique_num;

  /*
   * LOAD1 may have completed before LOAD2 reached rename. In that case,
   * release LOAD2's dependents immediately after their wake-up links exist.
   */
  if (readiness->load1_completed) {
    wake_up_ops(op, REG_DATA_DEP, wake_action);
    remove_readiness(readiness);
  }
}

void ideal_fusion_on_load_complete(Op* op,
                                   void (*wake_action)(Op*, Op*, uns)) {
  Ideal_Fusion_Readiness* readiness;

  if (!op || op->off_path || IDEAL_FUSION_PASS != 2 ||
      op->ideal_fusion_load_role != IDEAL_FUSION_LOAD1)
    return;

  readiness = get_or_create_readiness(op->ideal_fusion_micro_op_num);
  readiness->load1_completed = TRUE;

  /*
   * LOAD2 may already be waiting after rename. Its memory access is skipped,
   * so LOAD1 completion is the event that releases LOAD2's dependents.
   */
  if (readiness->load2 &&
      readiness->load2->unique_num == readiness->load2_unique_num &&
      readiness->load2->op_pool_valid) {
    wake_up_ops(readiness->load2, REG_DATA_DEP, wake_action);
    remove_readiness(readiness);
  }
}
