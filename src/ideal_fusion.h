/* Ideal Fusion (IFUSE) — pass-1 candidate identification + pass-2 actuation.
 *
 * Ports the candidate-finding logic from
 * STAR-Research/instruction-fusion@micro2026-generate-ideal-fusion-candidates
 * and the pass-2 actuation logic from @micro2026-ideal-fusion to litz-lab/scarab.
 *
 * Pass 1 (--log_ifuse_pairs 1) — identifies pairs of on-path memory loads
 *   (LOAD1, LOAD2) where:
 *     - both accesses fit inside the same 64B cache block,
 *     - no intervening on-path store hits that block,
 *     - LOAD2's on-path micro-op count minus LOAD1's is < FUSION_DISTANCE,
 *     - each load participates in at most one pair.
 *   Writes pairs to log_ifuse_pairs.txt as CSV.
 *
 * Pass 2 (--do_fusion 1 --fusion_candidates_file=<csv>) — reads the CSV,
 *   tags each LOAD1/LOAD2 op at fetch via global_micro_op_num lookup, rewrites
 *   LOAD2 as a NOP, and coordinates LOAD2's dependent wakeup off LOAD1's
 *   completion via the Load2 buffer (managed in map_stage.c / map.c).
 */

#ifndef __IDEAL_FUSION_H__
#define __IDEAL_FUSION_H__

#include "globals/global_types.h"
#include "op.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************************/
/* Pass-1 entry points (logging) */
void ideal_fusion_init(void);
void ideal_fusion_process_op(Op* op);
void ideal_fusion_finish(void);

/**************************************************************************************/
/* Pass-2 entry points (actuation) */

/* Loaded once at startup from --fusion_candidates_file; one entry per LOAD1 and
 * one per LOAD2 in two separate hash tables keyed by global_micro_op_num. */
typedef struct DoFusionMetadata {
  unsigned int global_micro_op_num;
  unsigned int partner_load_global_micro_op_num;
  Flag         is_load1;
  Addr         pc_addr;
  Addr         partner_pc_addr;
  Addr         block_offset;
  Addr         partner_block_offset;
  struct DoFusionMetadata* next;
} DoFusionMetadata;

/* Load2 buffer entry — coordinates LOAD1 completion with LOAD2 dependent wakeup.
 * Created by map_stage when LOAD1 enters; populated when LOAD2 enters; consumed
 * either by wake_up_ops (when LOAD1 completes with LOAD2 already waiting) or by
 * map_stage (when LOAD2 enters with LOAD1 already completed). The recycling
 * problem (Op* may be reused after a pipeline flush) is guarded by snapshotting
 * load2->unique_num and verifying identity before dereference. */
typedef struct Load2BufferEntry {
  Op*     load1;                              // pointer to LOAD1 op (set when LOAD1 enters map_stage)
  Counter load1_unique_num;                   // identity snapshot for recycling check
  Op*     load2;                              // pointer to LOAD2 op (NULL until LOAD2 enters map_stage)
  Counter load2_unique_num;                   // identity snapshot for recycling check
  Flag    load2_waiting;                      // LOAD2 has registered and is waiting on LOAD1
  Flag    load1_completed;                    // LOAD1 has executed
  Flag    pair_completed;                     // LOAD2's deps have been woken
  Counter load1_wake_cycle;                   // LOAD1's wake_cycle at completion (used to set LOAD2's
                                              //   wake_cycle when LOAD2 wakes its deps in the
                                              //   load1-already-completed case)
  Counter load1_done_cycle;                   // similar — for OP_DONE() consumers
  Counter load1_global_micro_op_num;
  Counter load2_global_micro_op_num;
  Counter creation_cycle;                     // for periodic cleanup
} Load2BufferEntry;

typedef struct Load2BufferNode {
  Load2BufferEntry        entry;
  struct Load2BufferNode* next;               // chain for hash collisions
} Load2BufferNode;

#define LOAD2_BUFFER_HT_SIZE 1000003

extern Load2BufferNode* load2_buffer_ht[LOAD2_BUFFER_HT_SIZE];

Load2BufferNode* find_load2_buffer_node(Counter load1_gmon, Counter load2_gmon);
Load2BufferNode* create_load2_buffer_node(Counter load1_gmon, Counter load2_gmon);
void             remove_load2_buffer_node(Load2BufferNode* node);

/* Called from icache_stage.c::icache_process_ops on every fetched op when
 * DO_FUSION is set. Looks up the op's global_micro_op_num in the loaded CSV
 * tables; if present, sets fusion_candidate_type and partner_micro_op_num.
 * For LOAD2, also rewrites the op as a NOP. */
void ideal_fusion_classify_at_icache(Op* op);

/* Called from icache_stage.c — wraps init + classify; mirrors the reference's
 * icache_do_fusion_tag_op_at_fetch entry point. Safe to call when DO_FUSION
 * is FALSE (returns immediately). */
void icache_do_fusion_tag_op_at_fetch(Op* op);

#ifdef __cplusplus
}
#endif

#endif /* __IDEAL_FUSION_H__ */
