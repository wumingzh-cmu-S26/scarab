/* Ideal Fusion (IFUSE) — pass-1 candidate identification + pass-2 actuation.
 *
 * Pass 1 (--log_ifuse_pairs 1): identifies pairs of on-path memory loads
 *   (LOAD1, LOAD2) where:
 *     - both accesses fit inside the same 64B cache block,
 *     - no intervening on-path store hits that block,
 *     - LOAD2's on-path micro-op count minus LOAD1's is < FUSION_DISTANCE,
 *     - each load participates in at most one pair.
 *   Writes pairs to log_ifuse_pairs.txt as CSV.
 *
 * Pass 2 (--do_fusion 1 --fusion_candidates_file=<csv>): reads the CSV,
 *   tags each LOAD1/LOAD2 op at fetch via global_micro_op_num lookup.
 *   This branch (ideal-fusion-remap-v2) wires the wakeup via a "remap" of
 *   reg_map (used for wake-up dependency tracking): LOAD2's update_map
 *   writes reg_map[LOAD2_arch_dst].op = LOAD1, so consumers of LOAD2's arch
 *   dst register their wakeup against LOAD1 and fire when LOAD1 completes.
 *
 * LOAD2 still allocates its OWN physical register at rename — no entry sharing
 * with LOAD1 (avoids num_refs / state-machine complications). Its entry is
 * marked PRODUCED immediately at alloc so consumer-time invariants hold.
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

void ideal_fusion_classify_at_icache(Op* op);
void icache_do_fusion_tag_op_at_fetch(Op* op);

/* I-Fuse ideal fusion: gmon -> (Op*, unique_num) for LOAD1, recorded at
 * LOAD1's update_map. LOAD2's update_map looks up to redirect reg_map. */
void ifuse_remap_record_load1(unsigned int load1_gmon, Op* op, Counter unique_num);
Op*  ifuse_remap_lookup_load1_op(unsigned int load1_gmon, Counter* out_unique_num);

#ifdef __cplusplus
}
#endif

#endif /* __IDEAL_FUSION_H__ */
