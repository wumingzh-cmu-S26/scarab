/* Ideal Fusion candidate identification (pass-1).
 * See ideal_fusion.h for the spec.
 *
 * Faithful port of STAR-Research/instruction-fusion@
 * micro2026-generate-ideal-fusion-candidates : src/icache_stage.c
 * (functions: determine_fusion_candidates, track_load,
 *  find_fusion_candidate, kill_old_candidates, cleanup_old_fusion_loads,
 *  same_cacheblock, log_fusion_candidate).
 */

#include "ideal_fusion.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "general.param.h"
#include "globals/assert.h"
#include "inst_info.h"
#include "op.h"
#include "statistics.h"
#include "table_info.h"

#define FUSION_CAND_HASH_TABLE_SIZE 4096
#define CACHELINE_SIZE 64
#define CLEANUP_PERIOD 400

typedef struct LoadMetadata_struct {
  Addr pc_addr;
  Addr virtual_addr;
  Addr cacheblock_addr;
  uns mem_size;
  Addr byte_in_block_offset;
  unsigned int global_micro_op_num;
  uns32 branch_history;
  Flag fused;
  struct LoadMetadata_struct* next;
  struct LoadMetadata_struct* prev;
} LoadMetadata;

static unsigned int global_micro_op_num = 0;
static unsigned int last_cleanup_micro_op_num = 0;
static Flag initialized = FALSE;

static LoadMetadata* fusion_candidate_table[FUSION_CAND_HASH_TABLE_SIZE];

static FILE* log_training_input = NULL;
static Flag log_train_open = FALSE;

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
    fprintf(stderr, "ideal_fusion: failed to open log file\n");
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

  nl->pc_addr = op->inst_info->addr;
  nl->virtual_addr = op->oracle_info.va;
  nl->cacheblock_addr = get_cacheblock_addr(op->oracle_info.va);
  nl->mem_size = ti->mem_size;
  nl->byte_in_block_offset = get_cacheblock_offset(op->oracle_info.va);
  nl->global_micro_op_num = global_micro_op_num;
  nl->branch_history = op->bp_pred_l0.pred_global_hist;
  nl->fused = FALSE;
  nl->next = NULL;
  nl->prev = NULL;

  unsigned int idx = hash_cacheblock(nl->cacheblock_addr);
  if (fusion_candidate_table[idx]) {
    nl->next = fusion_candidate_table[idx];
    fusion_candidate_table[idx]->prev = nl;
  }
  fusion_candidate_table[idx] = nl;
}

static LoadMetadata* find_fusion_candidate(Op* l2) {
  Addr cb = get_cacheblock_addr(l2->oracle_info.va);
  unsigned int idx = hash_cacheblock(cb);
  Table_Info* ti = &l2->inst_info->table_info;

  for (LoadMetadata* cur = fusion_candidate_table[idx]; cur; cur = cur->next) {
    if (cur->fused)
      continue;
    if (!same_cacheblock(cur->virtual_addr, cur->mem_size,
                         l2->oracle_info.va, ti->mem_size))
      continue;
    if (distance(cur->global_micro_op_num, global_micro_op_num) > FUSION_DISTANCE)
      continue;
    log_pair(cur, l2);
    return cur;
  }
  return NULL;
}

static void kill_old_candidates(Op* st) {
  Addr cb = get_cacheblock_addr(st->oracle_info.va);
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
      LoadMetadata* cur = *slot;
      Flag stale = cur->fused ||
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

void ideal_fusion_init(void) {
  if (initialized)
    return;
  for (int i = 0; i < FUSION_CAND_HASH_TABLE_SIZE; i++)
    fusion_candidate_table[i] = NULL;
  global_micro_op_num = 0;
  last_cleanup_micro_op_num = 0;
  open_log_if_needed();
  initialized = TRUE;
}

void ideal_fusion_process_op(Op* op) {
  if (!LOG_IFUSE_PAIRS)
    return;
  if (!initialized)
    ideal_fusion_init();
  if (!op || !op->inst_info)
    return;

  Table_Info* ti = &op->inst_info->table_info;

  if (!op->off_path) {
    global_micro_op_num++;
    if (ti->mem_type == MEM_LD)
      STAT_EVENT(op->proc_id, TOTAL_ON_PATH_MEM_LDS);
  }

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

void ideal_fusion_finish(void) {
  if (log_training_input) {
    fflush(log_training_input);
    fclose(log_training_input);
    log_training_input = NULL;
    log_train_open = FALSE;
  }
}
