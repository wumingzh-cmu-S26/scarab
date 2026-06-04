/* IFUSE — ideal fusion implementation.
 *
 * Pass 1 (logging) is a port of STAR-Research/instruction-fusion@
 *   micro2026-generate-ideal-fusion-candidates : src/icache_stage.c
 *   (find_fusion_candidate, track_load, kill_old_candidates, etc.).
 *
 * Pass 2 (actuation) is a port of @micro2026-ideal-fusion : src/icache_stage.c
 *   (icache_do_fusion_tag_op_at_fetch, ideal_fusion_classify_at_icache,
 *    lookup_load1/2_candidate_ideal, load_runtime_fusion_candidates).
 *
 * NOTE — the reference rewrites op->table_info fields in-place when LOAD2 is
 * identified at fetch. In the new Scarab, table_info is embedded in Inst_Info,
 * and Inst_Info can be shared across dynamic instances of the same static
 * instruction. For LOAD2, make a private Inst_Info copy before applying the
 * NOT_MEM rewrite so other dynamic instances are untouched. Normal ideal
 * fusion then bypasses LOAD2 backend execution and wakes its dependents from
 * LOAD1.
 */

#include "ideal_fusion.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "general.param.h"
#include "globals/assert.h"
#include "inst_info.h"
#include "op.h"
#include "statistics.h"
#include "table_info.h"

/**************************************************************************************/
/* Shared state (used by both passes) */

static unsigned int global_micro_op_num = 0;
static Flag         initialized         = FALSE;

/**************************************************************************************/
/* Pass 1 — candidate identification (logs to CSV) */

#define FUSION_CAND_HASH_TABLE_SIZE 4096
#define CACHELINE_SIZE              64
#define CLEANUP_PERIOD              400

typedef struct LoadMetadata_struct {
  Addr         pc_addr;
  Addr         virtual_addr;
  Addr         cacheblock_addr;
  uns          mem_size;
  Addr         byte_in_block_offset;
  unsigned int global_micro_op_num;
  uns32        branch_history;
  Flag         fused;
  struct LoadMetadata_struct* next;
  struct LoadMetadata_struct* prev;
} LoadMetadata;

static LoadMetadata* fusion_candidate_table[FUSION_CAND_HASH_TABLE_SIZE];
static unsigned int  last_cleanup_micro_op_num = 0;
static FILE*         log_training_input        = NULL;
static Flag          log_train_open            = FALSE;

static inline Addr get_cacheblock_addr(Addr va) {
  return va & ~((Addr)CACHELINE_SIZE - 1);
}

static inline Addr get_cacheblock_offset(Addr va) {
  return va & ((Addr)CACHELINE_SIZE - 1);
}

static inline unsigned int hash_cacheblock(Addr cb_addr) {
  uint64_t k = (uint64_t)cb_addr;
  k ^= k >> 33;
  k *= 0xff51afd7ed558ccdULL;
  k ^= k >> 33;
  return (unsigned int)(k % FUSION_CAND_HASH_TABLE_SIZE);
}

static inline unsigned int distance(unsigned int l1, unsigned int l2) {
  return l2 - l1;
}

static inline Flag same_cacheblock(Addr a1, uns s1, Addr a2, uns s2) {
  if ((a1 >> 6) != (a2 >> 6))
    return FALSE;
  Addr block = a1 & ~((Addr)0x3F);
  if (s1 == 0 || s2 == 0)
    return FALSE;
  if ((a1 + s1 - 1) >= (block + CACHELINE_SIZE))
    return FALSE;
  if ((a2 + s2 - 1) >= (block + CACHELINE_SIZE))
    return FALSE;
  return TRUE;
}

static void open_log_if_needed(void) {
  if (!LOG_IFUSE_PAIRS || log_train_open)
    return;
  log_training_input = fopen("log_ifuse_pairs.txt", "w");
  if (!log_training_input) {
    fprintf(stderr, "ideal_fusion: failed to open log_ifuse_pairs.txt\n");
    return;
  }
  fprintf(log_training_input,
          "load1_pc,load2_pc,load1_data_addr,load2_data_addr,"
          "load1_block_offset,load2_block_offset,load1_mem_size,load2_mem_size,"
          "load1_micro_op_num,load2_micro_op_num,"
          "load1_branch_history,load2_branch_history\n");
  fflush(log_training_input);
  log_train_open = TRUE;
}

static void log_pair(const LoadMetadata* l1, const Op* l2) {
  if (!log_train_open || !log_training_input)
    return;
  Addr l2_va = l2->oracle_info.va;
  fprintf(log_training_input,
          "%" PRIx64 ",%" PRIx64 ",%" PRIx64 ",%" PRIx64
          ",%" PRId64 ",%" PRId64 ",%u,%u,%u,%u,%" PRIu64 ",%" PRIu64 "\n",
          (uint64_t)l1->pc_addr, (uint64_t)l2->inst_info->addr,
          (uint64_t)l1->virtual_addr, (uint64_t)l2_va,
          (int64_t)l1->byte_in_block_offset,
          (int64_t)get_cacheblock_offset(l2_va),
          (unsigned)l1->mem_size,
          (unsigned)l2->inst_info->table_info.mem_size,
          l1->global_micro_op_num, global_micro_op_num,
          (uint64_t)l1->branch_history,
          (uint64_t)l2->bp_pred_l0.pred_global_hist);
  static int flush_counter = 0;
  if (++flush_counter % 1000 == 0)
    fflush(log_training_input);
}

static void track_load(Op* op) {
  Table_Info* ti = &op->inst_info->table_info;
  if (ti->mem_type != MEM_LD || ti->num_dest_regs == 0)
    return;

  LoadMetadata* nl = (LoadMetadata*)malloc(sizeof(LoadMetadata));
  if (!nl)
    return;

  nl->pc_addr              = op->inst_info->addr;
  nl->virtual_addr         = op->oracle_info.va;
  nl->cacheblock_addr      = get_cacheblock_addr(op->oracle_info.va);
  nl->mem_size             = ti->mem_size;
  nl->byte_in_block_offset = get_cacheblock_offset(op->oracle_info.va);
  nl->global_micro_op_num  = global_micro_op_num;
  nl->branch_history       = op->bp_pred_l0.pred_global_hist;
  nl->fused                = FALSE;
  nl->next                 = NULL;
  nl->prev                 = NULL;

  unsigned int idx = hash_cacheblock(nl->cacheblock_addr);
  if (fusion_candidate_table[idx]) {
    nl->next                          = fusion_candidate_table[idx];
    fusion_candidate_table[idx]->prev = nl;
  }
  fusion_candidate_table[idx] = nl;
}

static LoadMetadata* find_fusion_candidate(Op* l2) {
  Addr         cb  = get_cacheblock_addr(l2->oracle_info.va);
  unsigned int idx = hash_cacheblock(cb);
  Table_Info*  ti  = &l2->inst_info->table_info;

  for (LoadMetadata* cur = fusion_candidate_table[idx]; cur; cur = cur->next) {
    if (cur->fused)
      continue;
    if (!same_cacheblock(cur->virtual_addr, cur->mem_size,
                         l2->oracle_info.va, ti->mem_size))
      continue;
    if (distance(cur->global_micro_op_num, global_micro_op_num) >= FUSION_DISTANCE)
      continue;
    log_pair(cur, l2);
    return cur;
  }
  return NULL;
}

static void kill_old_candidates(Op* st) {
  Addr         cb  = get_cacheblock_addr(st->oracle_info.va);
  unsigned int idx = hash_cacheblock(cb);

  LoadMetadata* cur = fusion_candidate_table[idx];
  while (cur) {
    LoadMetadata* nxt = cur->next;
    if (cur->cacheblock_addr == cb && !cur->fused) {
      if (cur->prev)
        cur->prev->next = cur->next;
      else
        fusion_candidate_table[idx] = cur->next;
      if (cur->next)
        cur->next->prev = cur->prev;
      free(cur);
    }
    cur = nxt;
  }
}

static void cleanup_old_loads(unsigned int now) {
  for (int i = 0; i < FUSION_CAND_HASH_TABLE_SIZE; i++) {
    LoadMetadata** slot = &fusion_candidate_table[i];
    while (*slot) {
      LoadMetadata* cur   = *slot;
      Flag          stale = cur->fused ||
                            (now - cur->global_micro_op_num > FUSION_DISTANCE);
      if (stale) {
        *slot = cur->next;
        if (cur->next)
          cur->next->prev = cur->prev;
        free(cur);
      } else {
        slot = &cur->next;
      }
    }
  }
}

/**************************************************************************************/
/* Pass 2 — actuation (reads CSV, tags ops, drives buffer) */

#define DO_FUSION_HASH_SIZE 1000003

static DoFusionMetadata* do_fusion_table_idx_load1[DO_FUSION_HASH_SIZE];
static DoFusionMetadata* do_fusion_table_idx_load2[DO_FUSION_HASH_SIZE];
static DoFusionMetadata* do_fusion_table_pc_load1[DO_FUSION_HASH_SIZE];
static DoFusionMetadata* do_fusion_table_pc_load2[DO_FUSION_HASH_SIZE];
static DoFusionMetadata* do_fusion_table_pc_tail_load1[DO_FUSION_HASH_SIZE];
static DoFusionMetadata* do_fusion_table_pc_tail_load2[DO_FUSION_HASH_SIZE];
static Flag              do_fusion_loaded = FALSE;

/* Storage for the Load2 buffer. Functions live in map_stage.c — this is just
 * the array storage, declared extern in ideal_fusion.h. */
Load2BufferNode* load2_buffer_ht[LOAD2_BUFFER_HT_SIZE];

static inline unsigned int better_hash_u32(unsigned int key, unsigned int table_size) {
  key ^= key >> 17;
  key *= 0xed5ad4bb;
  key ^= key >> 11;
  key *= 0xac4c1b51;
  key ^= key >> 15;
  return key % table_size;
}

static inline unsigned int hash_pc_offset(Addr pc, Addr block_offset) {
  uint64_t key = (uint64_t)pc;
  key ^= (uint64_t)block_offset + 0x9e3779b97f4a7c15ULL + (key << 6) + (key >> 2);
  key ^= key >> 33;
  key *= 0xff51afd7ed558ccdULL;
  key ^= key >> 33;
  return (unsigned int)(key % DO_FUSION_HASH_SIZE);
}

static void load_fusion_candidates(void) {
  if (do_fusion_loaded)
    return;
  do_fusion_loaded = TRUE;  // mark loaded even on failure to avoid reattempts

  for (int i = 0; i < DO_FUSION_HASH_SIZE; i++) {
    do_fusion_table_idx_load1[i] = NULL;
    do_fusion_table_idx_load2[i] = NULL;
    do_fusion_table_pc_load1[i] = NULL;
    do_fusion_table_pc_load2[i] = NULL;
    do_fusion_table_pc_tail_load1[i] = NULL;
    do_fusion_table_pc_tail_load2[i] = NULL;
  }
  for (int i = 0; i < LOAD2_BUFFER_HT_SIZE; i++) {
    load2_buffer_ht[i] = NULL;
  }

  const char* path = FUSION_CANDIDATES_FILE;
  if (!path || !*path)
    path = "log_ifuse_pairs.txt";

  FILE* f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "ideal_fusion: cannot open --fusion_candidates_file '%s'\n", path);
    return;
  }

  char line[1024];
  if (!fgets(line, sizeof(line), f)) {  // skip header
    fclose(f);
    return;
  }

  unsigned int loaded = 0;
  while (fgets(line, sizeof(line), f)) {
    uint64_t l1_pc, l2_pc, l1_va, l2_va, l1_hist, l2_hist;
    int64_t  l1_off, l2_off;
    unsigned l1_size, l2_size, l1_gmon, l2_gmon, force_pipeline = 0;
    int      n = sscanf(line,
                        "%" SCNx64 ",%" SCNx64 ",%" SCNx64 ",%" SCNx64
                        ",%" SCNd64 ",%" SCNd64 ",%u,%u,%u,%u,%" SCNu64 ",%" SCNu64 ",%u",
                        &l1_pc, &l2_pc, &l1_va, &l2_va, &l1_off, &l2_off,
                        &l1_size, &l2_size, &l1_gmon, &l2_gmon, &l1_hist, &l2_hist,
                        &force_pipeline);
    if (n < 12)
      continue;

    DoFusionMetadata* m1 = (DoFusionMetadata*)malloc(sizeof(DoFusionMetadata));
    if (!m1)
      break;
    m1->global_micro_op_num              = l1_gmon;
    m1->partner_load_global_micro_op_num = l2_gmon;
    m1->actual_global_micro_op_num       = 0;
    m1->partner_actual_global_micro_op_num = 0;
    m1->is_load1                         = TRUE;
    m1->consumed                         = FALSE;
    m1->pc_addr                          = (Addr)l1_pc;
    m1->partner_pc_addr                  = (Addr)l2_pc;
    m1->block_offset                     = (Addr)l1_off;
    m1->partner_block_offset             = (Addr)l2_off;
    m1->force_load2_pipeline             = (n == 13 && force_pipeline != 0);
    m1->partner                          = NULL;
    unsigned int i1                      = better_hash_u32(l1_gmon, DO_FUSION_HASH_SIZE);
    m1->next_gmon                        = do_fusion_table_idx_load1[i1];
    do_fusion_table_idx_load1[i1]        = m1;
    unsigned int p1                      = hash_pc_offset((Addr)l1_pc,
                                                          (Addr)l1_off);
    m1->next_pc                          = NULL;
    if (do_fusion_table_pc_tail_load1[p1])
      do_fusion_table_pc_tail_load1[p1]->next_pc = m1;
    else
      do_fusion_table_pc_load1[p1] = m1;
    do_fusion_table_pc_tail_load1[p1] = m1;

    DoFusionMetadata* m2 = (DoFusionMetadata*)malloc(sizeof(DoFusionMetadata));
    if (!m2)
      break;
    m2->global_micro_op_num              = l2_gmon;
    m2->partner_load_global_micro_op_num = l1_gmon;
    m2->actual_global_micro_op_num       = 0;
    m2->partner_actual_global_micro_op_num = 0;
    m2->is_load1                         = FALSE;
    m2->consumed                         = FALSE;
    m2->pc_addr                          = (Addr)l2_pc;
    m2->partner_pc_addr                  = (Addr)l1_pc;
    m2->block_offset                     = (Addr)l2_off;
    m2->partner_block_offset             = (Addr)l1_off;
    m2->force_load2_pipeline             = (n == 13 && force_pipeline != 0);
    m2->partner                          = m1;
    m1->partner                          = m2;
    unsigned int i2                      = better_hash_u32(l2_gmon, DO_FUSION_HASH_SIZE);
    m2->next_gmon                        = do_fusion_table_idx_load2[i2];
    do_fusion_table_idx_load2[i2]        = m2;
    unsigned int p2                      = hash_pc_offset((Addr)l2_pc,
                                                          (Addr)l2_off);
    m2->next_pc                          = NULL;
    if (do_fusion_table_pc_tail_load2[p2])
      do_fusion_table_pc_tail_load2[p2]->next_pc = m2;
    else
      do_fusion_table_pc_load2[p2] = m2;
    do_fusion_table_pc_tail_load2[p2] = m2;

    loaded++;
  }
  fclose(f);
  INC_STAT_EVENT(0, IFUSE_CANDIDATE_PAIRS_LOADED, loaded);
  fprintf(stderr, "ideal_fusion: loaded %u candidate pairs from %s\n", loaded, path);
}

static DoFusionMetadata* lookup_and_remove(DoFusionMetadata** table,
                                           unsigned int       gmon) {
  unsigned int       idx  = better_hash_u32(gmon, DO_FUSION_HASH_SIZE);
  DoFusionMetadata** slot = &table[idx];
  while (*slot) {
    if ((*slot)->global_micro_op_num == gmon) {
      DoFusionMetadata* found = *slot;
      if (!found->consumed)
        return found;
    }
    slot = &(*slot)->next_gmon;
  }
  return NULL;
}

static DoFusionMetadata* lookup_by_pc_offset(DoFusionMetadata** table,
                                             Addr                pc,
                                             Addr                block_offset) {
  unsigned int       idx  = hash_pc_offset(pc, block_offset);
  DoFusionMetadata** slot = &table[idx];
  while (*slot) {
    DoFusionMetadata* cur = *slot;
    if (cur->consumed) {
      *slot = cur->next_pc;
      continue;
    }
    if (cur->pc_addr == pc && cur->block_offset == block_offset)
      return cur;
    slot = &cur->next_pc;
  }
  return NULL;
}

static inline Flag load2_candidate_partner_ready(const DoFusionMetadata* m,
                                                 Counter current_gmon) {
  return m && !m->is_load1 && m->partner_actual_global_micro_op_num &&
         m->partner_actual_global_micro_op_num < current_gmon;
}

static DoFusionMetadata* lookup_load2_by_pc_offset_ready(Addr    pc,
                                                         Addr    block_offset,
                                                         Counter current_gmon) {
  unsigned int       idx  = hash_pc_offset(pc, block_offset);
  DoFusionMetadata** slot = &do_fusion_table_pc_load2[idx];
  while (*slot) {
    DoFusionMetadata* cur = *slot;
    if (cur->consumed) {
      *slot = cur->next_pc;
      continue;
    }
    if (cur->pc_addr == pc && cur->block_offset == block_offset &&
        load2_candidate_partner_ready(cur, current_gmon))
      return cur;
    slot = &cur->next_pc;
  }
  return NULL;
}

static void rewrite_load2_as_not_mem(Op* op) {
  Inst_Info* rewritten = (Inst_Info*)malloc(sizeof(Inst_Info));
  ASSERT(op->proc_id, rewritten);
  *rewritten = *op->inst_info;

  rewritten->table_info.mem_type = NOT_MEM;
  rewritten->table_info.mem_size = 0;
  rewritten->extra_ld_latency    = 0;
  /* Match the micro2026-ideal-fusion reference: fused LOAD2 becomes a
   * non-memory op with one-cycle latency. */
  rewritten->latency             = 1;

  op->inst_info               = rewritten;
  op->oracle_info.mem_size    = 0;
  op->ifuse_private_inst_info = TRUE;
}

static void audit_candidate_match(Op* op, const DoFusionMetadata* m) {
  Addr actual_offset = get_cacheblock_offset(op->oracle_info.va);

  if (m->is_load1)
    STAT_EVENT(op->proc_id, IFUSE_LOAD1_MATCHED);
  else
    STAT_EVENT(op->proc_id, IFUSE_LOAD2_MATCHED);

  if (op->inst_info->addr != m->pc_addr) {
    STAT_EVENT(op->proc_id,
               m->is_load1 ? IFUSE_LOAD1_PC_MISMATCH : IFUSE_LOAD2_PC_MISMATCH);
  }

  if (actual_offset != m->block_offset) {
    STAT_EVENT(op->proc_id,
               m->is_load1 ? IFUSE_LOAD1_OFFSET_MISMATCH :
                             IFUSE_LOAD2_OFFSET_MISMATCH);
  }
}

static inline Flag candidate_identity_matches(Op* op, const DoFusionMetadata* m) {
  return op->inst_info->addr == m->pc_addr &&
         get_cacheblock_offset(op->oracle_info.va) == m->block_offset;
}

static void audit_gmon_identity_mismatch(Op* op, const DoFusionMetadata* m) {
  if (op->inst_info->addr != m->pc_addr)
    STAT_EVENT(op->proc_id,
               m->is_load1 ? IFUSE_LOAD1_PC_MISMATCH : IFUSE_LOAD2_PC_MISMATCH);
  if (get_cacheblock_offset(op->oracle_info.va) != m->block_offset)
    STAT_EVENT(op->proc_id,
               m->is_load1 ? IFUSE_LOAD1_OFFSET_MISMATCH :
                             IFUSE_LOAD2_OFFSET_MISMATCH);
}

static void record_actual_match(Op* op, DoFusionMetadata* m) {
  m->actual_global_micro_op_num = (Counter)op->global_micro_op_num;
  if (m->partner)
    m->partner->partner_actual_global_micro_op_num =
        (Counter)op->global_micro_op_num;
}

static Counter candidate_partner_gmon(const DoFusionMetadata* m) {
  return m->partner_actual_global_micro_op_num ?
             m->partner_actual_global_micro_op_num :
             (Counter)m->partner_load_global_micro_op_num;
}

static Flag ifuse_pair_uses_load2_bypass(Counter self_gmon, Counter partner_gmon,
                                         Flag force_load2_pipeline) {
  if (!IFUSE_LOAD2_BYPASS)
    return FALSE;

  if (IFUSE_LOAD2_PIPELINE_CSV_FLAG && force_load2_pipeline)
    return FALSE;

  Counter dist = self_gmon > partner_gmon ? self_gmon - partner_gmon : partner_gmon - self_gmon;
  if (IFUSE_LOAD2_PIPELINE_MAX_DIST && dist <= IFUSE_LOAD2_PIPELINE_MAX_DIST)
    return FALSE;

  return TRUE;
}

void ideal_fusion_classify_at_icache(Op* op) {
  if (!DO_FUSION)
    return;
  if (!op || !op->inst_info)
    return;
  if (op->off_path)
    return;

  Table_Info* ti = &op->inst_info->table_info;
  if (ti->mem_type != MEM_LD)
    return;
  if (op->global_micro_op_num == 0)
    return;

  /* fusion_candidate_type defaults to NOT_FUSION_CANDIDATE via op_pool zero-init */

  DoFusionMetadata* m = lookup_and_remove(do_fusion_table_idx_load1,
                                          op->global_micro_op_num);
  Addr actual_offset = get_cacheblock_offset(op->oracle_info.va);
  if (m && IFUSE_PC_FALLBACK && !candidate_identity_matches(op, m)) {
    audit_gmon_identity_mismatch(op, m);
    m = NULL;
  }
  if (!m && IFUSE_PC_FALLBACK) {
    m = lookup_by_pc_offset(do_fusion_table_pc_load1,
                            op->inst_info->addr,
                            actual_offset);
    if (m)
      STAT_EVENT(op->proc_id, IFUSE_LOAD1_PC_FALLBACK_MATCHED);
  }
  if (m) {
    audit_candidate_match(op, m);
    record_actual_match(op, m);
    m->consumed               = TRUE;
    op->fusion_candidate_type = LOAD1;
    op->partner_micro_op_num  = candidate_partner_gmon(m);
    op->ifuse_load2_bypass =
        ifuse_pair_uses_load2_bypass((Counter)op->global_micro_op_num,
                                     (Counter)op->partner_micro_op_num,
                                     m->force_load2_pipeline);
    return;
  }

  m = lookup_and_remove(do_fusion_table_idx_load2, op->global_micro_op_num);
  if (m && IFUSE_PC_FALLBACK && !candidate_identity_matches(op, m)) {
    audit_gmon_identity_mismatch(op, m);
    m = NULL;
  }
  if (m && IFUSE_PC_FALLBACK &&
      !load2_candidate_partner_ready(m, (Counter)op->global_micro_op_num))
    m = NULL;
  if (!m && IFUSE_PC_FALLBACK) {
    m = lookup_load2_by_pc_offset_ready(op->inst_info->addr,
                                        actual_offset,
                                        (Counter)op->global_micro_op_num);
    if (m)
      STAT_EVENT(op->proc_id, IFUSE_LOAD2_PC_FALLBACK_MATCHED);
  }
  if (m) {
    audit_candidate_match(op, m);
    record_actual_match(op, m);
    m->consumed               = TRUE;
    op->fusion_candidate_type = LOAD2;
    op->partner_micro_op_num  = candidate_partner_gmon(m);
    op->ifuse_load2_bypass =
        ifuse_pair_uses_load2_bypass((Counter)op->global_micro_op_num,
                                     (Counter)op->partner_micro_op_num,
                                     m->force_load2_pipeline);
    rewrite_load2_as_not_mem(op);
    STAT_EVENT(op->proc_id, NUM_FUSED_PAIRS_IDEAL);
  }
}

void icache_do_fusion_tag_op_at_fetch(Op* op) {
  /* Compatibility wrapper — mirrors the reference's entry point name. The
   * actual unified hook is ideal_fusion_process_op() called from
   * icache_stage.c::icache_process_ops, which handles both passes. */
  ideal_fusion_classify_at_icache(op);
}

/**************************************************************************************/
/* Unified per-op entry point — called from icache_stage.c at fetch */

void ideal_fusion_init(void) {
  if (initialized)
    return;
  for (int i = 0; i < FUSION_CAND_HASH_TABLE_SIZE; i++)
    fusion_candidate_table[i] = NULL;
  global_micro_op_num       = 0;
  last_cleanup_micro_op_num = 0;
  open_log_if_needed();
  if (DO_FUSION)
    load_fusion_candidates();
  initialized = TRUE;
}

void ideal_fusion_process_op(Op* op) {
  /* Cheap early-out when neither pass is enabled */
  if (!LOG_IFUSE_PAIRS && !DO_FUSION)
    return;
  if (!op || !op->inst_info)
    return;

  if (!initialized)
    ideal_fusion_init();

  Table_Info* ti = &op->inst_info->table_info;

  /* Assign on-path gmon — used by both passes. */
  if (!op->off_path) {
    global_micro_op_num++;
    op->global_micro_op_num = global_micro_op_num;
    if (ti->mem_type == MEM_LD)
      STAT_EVENT(op->proc_id, TOTAL_ON_PATH_MEM_LDS);
  }

  /* Pass 2: tag this op based on the loaded CSV. Runs before pass-1 logging
   * so a single binary doesn't normally have both flags on (but if it did,
   * the order doesn't matter — they consult different state). */
  if (DO_FUSION)
    ideal_fusion_classify_at_icache(op);

  /* Pass 1: run candidate identification + CSV logging. */
  if (LOG_IFUSE_PAIRS) {
    if (!op->off_path &&
        global_micro_op_num - last_cleanup_micro_op_num >= FUSION_DISTANCE) {
      last_cleanup_micro_op_num = global_micro_op_num;
      if (global_micro_op_num % CLEANUP_PERIOD == 0)
        cleanup_old_loads(global_micro_op_num);
    }

    if (op->off_path)
      return;

    if (ti->mem_type == MEM_ST) {
      kill_old_candidates(op);
      return;
    }

    if (ti->mem_type == MEM_LD && ti->num_dest_regs > 0) {
      LoadMetadata* l1 = find_fusion_candidate(op);
      if (l1) {
        l1->fused = TRUE;
        STAT_EVENT(op->proc_id, NUM_PAIRS_FUSED);
      } else {
        track_load(op);
      }
    }
  }
}

void ideal_fusion_finish(void) {
  if (log_training_input) {
    fflush(log_training_input);
    fclose(log_training_input);
    log_training_input = NULL;
    log_train_open     = FALSE;
  }
}
