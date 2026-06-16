#ifndef IFUSE_POLICY_H
#define IFUSE_POLICY_H

#include "../globals/global_types.h"
#include "../globals/global_defs.h"

/*
 * Opt-in adaptive gate for dynamic IFuse prediction. Training can continue
 * while prediction is gated off; this policy only decides whether frontend
 * LOAD1/LOAD2 classification should consume FCT/APT/ACI state right now.
 */
Flag ifuse_policy_prediction_allowed(uns proc_id);

/* Called once for each cycle where ROB retirement is blocked by a D-cache miss. */
void ifuse_policy_observe_dc_miss_blocked_cycle(uns proc_id);

#endif /* IFUSE_POLICY_H */
