/* Ideal Fusion candidate identification (pass-1).
 *
 * Ports the candidate-finding logic from
 * STAR-Research/instruction-fusion@micro2026-generate-ideal-fusion-candidates
 * (src/icache_stage.c) to litz-lab/scarab.
 *
 * Identifies pairs of on-path memory loads (LOAD1 -> LOAD2) where:
 *   - both accesses fit inside the same 64B cache block,
 *   - no intervening on-path store hits that block,
 *   - LOAD2's on-path micro-op count minus LOAD1's is < FUSION_DISTANCE,
 *   - each load participates in at most one pair.
 *
 * Pairs are written to log_train_input_fusion_candidates.txt (CSV) when
 * --log_train_input_candidates 1 is set on the cmd line.
 */

#ifndef __IDEAL_FUSION_H__
#define __IDEAL_FUSION_H__

#include "globals/global_types.h"
#include "op.h"

#ifdef __cplusplus
extern "C" {
#endif

void ideal_fusion_init(void);
void ideal_fusion_process_op(Op* op);
void ideal_fusion_finish(void);

#ifdef __cplusplus
}
#endif

#endif /* __IDEAL_FUSION_H__ */
