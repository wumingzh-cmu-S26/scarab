/*
 * Copyright 2020 HPS/SAFARI Research Groups
 * Copyright 2025 Litz Lab
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/***************************************************************************************
 * File         : map_stage.c
 * Author       : HPS Research Group, Litz Lab
 * Date         : 2/4/1999, 3/2025
 * Description  :
 ***************************************************************************************/

#include "map_stage.h"

#include "globals/assert.h"
#include "globals/debug_stage.h"
#include "globals/global_defs.h"
#include "globals/global_types.h"
#include "globals/global_vars.h"
#include "globals/utils.h"

#include "debug/debug.param.h"
#include "debug/debug_macros.h"
#include "debug/debug_print.h"

#include "core.param.h"
#include "memory/memory.param.h"

#include "bp/bp.h"

#include "ft.h"
#include "map.h"
#include "map_rename.h"
#include "model.h"
#include "op_pool.h"
#include "statistics.h"
#include "thread.h"

#include "ideal_fusion.h"

/**************************************************************************************/
/* Macros */
#define DEBUG(proc_id, args...) _DEBUG(proc_id, DEBUG_MAP_STAGE, ##args)
#define STAGE_MAX_OP_COUNT ISSUE_WIDTH
#define STAGE_MAX_DEPTH MAP_CYCLES

/**************************************************************************************/
/* Global Variables */

Map_Stage* map = NULL;

/**************************************************************************************/
/* Local prototypes */

static inline void stage_process_op(Op*);
static inline void map_stage_collect_stat(Flag, Flag);
static inline void map_stage_fetch_op(Stage_Data*);

/**************************************************************************************/
/* set_map_stage: */

void set_map_stage(Map_Stage* new_map) {
  map = new_map;
}

/**************************************************************************************/
/* init_map_stage: */

void init_map_stage(uns8 proc_id, const char* name) {
  uns ii;
  ASSERT(proc_id, map);
  ASSERT(proc_id, STAGE_MAX_DEPTH > 0);
  DEBUG(proc_id, "Initializing %s stage\n", name);

  memset(map, 0, sizeof(Map_Stage));
  map->proc_id = proc_id;

  map->sds = (Stage_Data*)malloc(sizeof(Stage_Data) * STAGE_MAX_DEPTH);
  for (ii = 0; ii < STAGE_MAX_DEPTH; ii++) {
    Stage_Data* cur = &map->sds[ii];
    /* Stage_Data::name is only used for debugging/printing; reuse the long-lived
     * stage name pointer passed into init_map_stage().
     */
    cur->name = (char*)name;
    cur->max_op_count = STAGE_MAX_OP_COUNT;
    cur->ops = (Op**)malloc(sizeof(Op*) * STAGE_MAX_OP_COUNT);
  }
  map->last_sd = &map->sds[0];
  map->off_path = 0;
  map->next_op_num = 1;
  reset_map_stage();
}

/**************************************************************************************/
/* reset_map_stage: */

void reset_map_stage() {
  uns ii, jj;
  ASSERT(0, map);
  for (ii = 0; ii < STAGE_MAX_DEPTH; ii++) {
    Stage_Data* cur = &map->sds[ii];
    cur->op_count = 0;
    for (jj = 0; jj < STAGE_MAX_OP_COUNT; jj++)
      cur->ops[jj] = NULL;
  }

  map->reg_file_stall = FALSE;
}

/**************************************************************************************/
/* recover_map_stage: */

void recover_map_stage() {
  uns ii, jj, kk;
  map->off_path = 0;
  ASSERT(0, map);
  for (ii = 0; ii < STAGE_MAX_DEPTH; ii++) {
    Flag flushed = FALSE;
    Stage_Data* cur = &map->sds[ii];
    cur->op_count = 0;

    for (jj = 0, kk = 0; jj < STAGE_MAX_OP_COUNT; jj++) {
      if (cur->ops[jj]) {
        if (IS_FLUSHING_OP(cur->ops[jj])) {
          op_select_bp_pred_info(cur->ops[jj], BP_PRED_MAIN);
          DEBUG(map->proc_id, "Recovery op found in Map stage:%u slot:%u op_num:%llu off_path:%u addr:0x%llx\n", ii, jj,
                (unsigned long long)cur->ops[jj]->op_num, cur->ops[jj]->off_path,
                (unsigned long long)cur->ops[jj]->inst_info->addr);
        }
        if (FLUSH_OP(cur->ops[jj])) {
          DEBUG(map->proc_id, "Map flushing op_num:%llu off_path:%u\n", (unsigned long long)cur->ops[jj]->op_num,
                cur->ops[jj]->off_path);
          flushed = TRUE;
          ASSERT(map->proc_id, cur->ops[jj]->off_path);
          if (cur->ops[jj]->parent_FT)
            ft_free_op(cur->ops[jj]);
          cur->ops[jj] = NULL;
        } else {
          Op* op = cur->ops[jj];
          cur->op_count++;
          cur->ops[jj] = NULL;  // collapse the ops
          cur->ops[kk++] = op;
        }
      }
    }

    if (cur->op_count > 0 && flushed) {
      Op* op = cur->ops[cur->op_count - 1];
      assert_ft_after_recovery(map->proc_id, op, bp_recovery_info->recovery_fetch_addr);
    }
  }

  if (map->next_op_num > bp_recovery_info->recovery_op_num) {
    map->next_op_num = bp_recovery_info->recovery_op_num + 1;
    DEBUG(map->proc_id, "Recovering map->next_op_num to %llu\n", map->next_op_num);
  }
}

/**************************************************************************************/
/* debug_map_stage: */

void debug_map_stage() {
  uns ii;
  for (ii = 0; ii < STAGE_MAX_DEPTH; ii++) {
    Stage_Data* cur = &map->sds[STAGE_MAX_DEPTH - ii - 1];
    DPRINTF("# %-10s  op_count:%d\n", cur->name, cur->op_count);
    DPRINTF("# %-10s  op_nums:", cur->name);
    print_stage_op_nums(GLOBAL_DEBUG_STREAM, cur->ops, cur->op_count);
    DPRINTF("\n");
    print_op_array(GLOBAL_DEBUG_STREAM, cur->ops, STAGE_MAX_OP_COUNT, STAGE_MAX_OP_COUNT);
  }
}

/**************************************************************************************/
/* map_cycle: */

void update_map_stage(Stage_Data* src_sd) {
  /* stall if the renaming table is full */
  if (!reg_file_available(STAGE_MAX_OP_COUNT)) {
    map->reg_file_stall = TRUE;
    DEBUG(map->proc_id,
          "Map Stage stalled (reg_file_full) last_sd_op_num:%s last_sd_op_count:%d src_op_num:%s src_op_count:%d\n",
          (map->last_sd->op_count && map->last_sd->ops[0]) ? unsstr64(map->last_sd->ops[0]->op_num) : "none",
          map->last_sd->op_count, (src_sd->op_count && src_sd->ops[0]) ? unsstr64(src_sd->ops[0]->op_num) : "none",
          src_sd->op_count);
    STAT_EVENT(map->proc_id, MAP_STAGE_STALL_ITSELF);
    return;
  }
  map->reg_file_stall = FALSE;
  STAT_EVENT(map->proc_id, MAP_STAGE_NOT_STALL_ITSELF);

  Flag stall = (map->last_sd->op_count > 0);
  Flag starved = (src_sd->op_count == 0);
  map_stage_collect_stat(stall, starved);

  /* do all the intermediate stages */
  for (int ii = 0; ii < STAGE_MAX_DEPTH - 1; ii++) {
    Stage_Data* cur = &map->sds[ii];
    Stage_Data* prev = &map->sds[ii + 1];

    if (cur->op_count)
      continue;

    Op** temp = cur->ops;
    cur->ops = prev->ops;
    prev->ops = temp;
    cur->op_count = prev->op_count;
    prev->op_count = 0;
  }

  /* do the first map stage */
  if (map->sds[STAGE_MAX_DEPTH - 1].op_count == 0 && !starved) {
    map_stage_fetch_op(src_sd);
  }

  /* if the last map stage is stalled, don't re-process the ops  */
  if (stall) {
    DEBUG(map->proc_id, "Map Stage stalled op_num:%s last_sd_op_count:%d\n",
          (map->last_sd->op_count && map->last_sd->ops[0]) ? unsstr64(map->last_sd->ops[0]->op_num) : "none",
          map->last_sd->op_count);
    return;
  }

  /* now map the ops in the last map stage */
  for (int ii = 0; ii < map->last_sd->op_count; ii++) {
    Op* op = map->last_sd->ops[ii];
    ASSERT(map->proc_id, op != NULL);
    stage_process_op(op);
  }
}

/**************************************************************************************/
/* IFUSE — Load2 buffer hash table accessors.
 *
 * The buffer coordinates LOAD1 completion with LOAD2 dependent wakeup.
 * Storage (load2_buffer_ht[]) lives in ideal_fusion.c; the access primitives
 * live here so they're co-located with the per-op handler that drives them. */

static inline unsigned int load2_buffer_hash(Counter a, Counter b) {
  const uint32_t prime1 = 0x9e3779b1;
  const uint32_t prime2 = 0x85ebca6b;
  uint32_t       h      = (uint32_t)a * prime1;
  h ^= (uint32_t)b * prime2;
  h ^= h >> 16;
  return h % LOAD2_BUFFER_HT_SIZE;
}

Load2BufferNode* find_load2_buffer_node(Counter load1_gmon, Counter load2_gmon) {
  unsigned int     idx = load2_buffer_hash(load1_gmon, load2_gmon);
  Load2BufferNode* cur = load2_buffer_ht[idx];
  while (cur) {
    if (cur->entry.load1_global_micro_op_num == load1_gmon)
      return cur;
    cur = cur->next;
  }
  return NULL;
}

Load2BufferNode* create_load2_buffer_node(Counter load1_gmon, Counter load2_gmon) {
  Load2BufferNode* node = (Load2BufferNode*)malloc(sizeof(Load2BufferNode));
  if (!node)
    return NULL;
  memset(&node->entry, 0, sizeof(Load2BufferEntry));
  node->entry.load1_global_micro_op_num = load1_gmon;
  node->entry.creation_cycle            = cycle_count;
  unsigned int idx                      = load2_buffer_hash(load1_gmon, load2_gmon);
  node->next                            = load2_buffer_ht[idx];
  load2_buffer_ht[idx]                  = node;
  return node;
}

void remove_load2_buffer_node(Load2BufferNode* node) {
  if (!node)
    return;
  Counter           k    = node->entry.load1_global_micro_op_num;
  unsigned int      idx  = load2_buffer_hash(k, k);
  Load2BufferNode** slot = &load2_buffer_ht[idx];
  while (*slot) {
    if (*slot == node) {
      *slot = node->next;
      free(node);
      return;
    }
    slot = &(*slot)->next;
  }
  /* Not in chain (already removed?). Defensive free. */
  free(node);
}

/* Per-op IFUSE handler at map-stage. Called from stage_process_op AFTER the
 * standard add_to_wake_up_lists, so that wake_up_ops on LOAD2 (in the
 * load1_already_completed branch) finds a populated wake_up list. */
static inline void ifuse_map_handle(Op* op) {
  if (!DO_FUSION)
    return;
  if (op->off_path)
    return;
  if (op->fusion_candidate_type == NOT_FUSION_CANDIDATE)
    return;

  if (op->fusion_candidate_type == LOAD1) {
    Counter          load1_gmon = (Counter)op->global_micro_op_num;
    Load2BufferNode* node       = find_load2_buffer_node(load1_gmon, load1_gmon);
    if (!node) {
      node = create_load2_buffer_node(load1_gmon, load1_gmon);
    }
    /* If node already existed, leave its state alone — earlier instance from
     * before a recovery may have populated it; this new LOAD1 (same gmon should
     * not actually recur, since gmons are monotonically assigned at fetch) just
     * reuses the slot. */
  } else if (op->fusion_candidate_type == LOAD2) {
    Counter          load1_gmon = (Counter)op->partner_micro_op_num;
    Load2BufferNode* node       = find_load2_buffer_node(load1_gmon, load1_gmon);
    if (!node) {
      /* LOAD1 hasn't reached map_stage yet — shouldn't happen because ops
       * flow through map_stage in program order, but be defensive. */
      node                                    = create_load2_buffer_node(load1_gmon, load1_gmon);
      node->entry.load1_global_micro_op_num   = load1_gmon;
    }
    node->entry.load2                     = op;
    node->entry.load2_unique_num          = op->unique_num;  /* recycling guard */
    node->entry.load2_global_micro_op_num = (Counter)op->global_micro_op_num;

    if (node->entry.load1_completed) {
      /* LOAD1 already finished while LOAD2 was upstream; LOAD1's wake_up
       * skipped LOAD2's deps because LOAD2 wasn't here yet. Wake them now,
       * then clean up the entry. */
      wake_up_ops(op, REG_DATA_DEP, model->wake_hook);
      node->entry.pair_completed = TRUE;
      remove_load2_buffer_node(node);
    } else {
      node->entry.load2_waiting  = TRUE;
      node->entry.pair_completed = FALSE;
    }
  }
}

/**************************************************************************************/
/* Local methods */

static inline void stage_process_op(Op* op) {
  ASSERT(map->proc_id, map->proc_id == td->proc_id);

  /* add to sequential op list */
  add_to_seq_op_list(td, op);
  ASSERT(map->proc_id, td->seq_op_list.count <= op_pool_active_ops);

  /* map the op based on true dependencies & set information in op->oracle_info */
  thread_map_op(op);
  thread_map_mem_dep(op);

  /* register renaming allocation */
  reg_file_rename(op);

  /* setting wake up lists */
  add_to_wake_up_lists(op, model->wake_hook);

  /* IFUSE: coordinate fused load pair via Load2 buffer */
  ifuse_map_handle(op);
}

static inline void map_stage_collect_stat(Flag stall, Flag starved) {
  if (map->off_path) {
    STAT_EVENT(map->proc_id, MAP_STAGE_OFF_PATH);
    return;
  }

  if (stall)
    STAT_EVENT(map->proc_id, MAP_STAGE_STALLED);
  else
    STAT_EVENT(map->proc_id, MAP_STAGE_NOT_STALLED);

  if (starved)
    STAT_EVENT(map->proc_id, MAP_STAGE_STARVED);
  else
    STAT_EVENT(map->proc_id, MAP_STAGE_NOT_STARVED);
}

static inline void map_stage_fetch_op(Stage_Data* src_sd) {
  Stage_Data* first_sd = &map->sds[STAGE_MAX_DEPTH - 1];
  int op_count_before_fetch = src_sd->op_count;

  for (int ii = 0; ii < op_count_before_fetch; ii++) {
    Op* op = src_sd->ops[ii];
    ASSERT(map->proc_id, op->op_num == map->next_op_num);
    DEBUG(map->proc_id, "Fetching opnum=%llu at idx=%i\n", op->op_num, ii);

    op->map_cycle = cycle_count;
    first_sd->ops[ii] = op;
    first_sd->op_count++;

    src_sd->ops[ii] = NULL;
    src_sd->op_count--;

    map->next_op_num++;
    if (op->off_path) {
      map->off_path = 1;
    }
  }

  // TODO: probably should count number of on-path ops.
  if (!map->off_path)
    STAT_EVENT(map->proc_id, MAP_STAGE_RECEIVED_OPS_0 + first_sd->op_count);

  // Any stage can receive a mix of on/off-path ops in a single cycle.
  ASSERT(map->proc_id, first_sd->op_count <= MAP_STAGE_RECEIVED_OPS_MAX);
}
