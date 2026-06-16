#include "ifuse_policy.h"

#include <string.h>

#include "../globals/global_defs.h"
#include "../globals/global_vars.h"
#include "../statistics.h"
#include "ifuse.param.h"

typedef struct IFuseMemGateState {
    Flag initialized;
    Flag enabled;
    Counter window_start_cycle;
    Counter dc_blocked_cycles;
} IFuseMemGateState;

static IFuseMemGateState ifuse_mem_gate_state[MAX_NUM_PROCS];

static void ifuse_policy_init_core(uns proc_id) {
    IFuseMemGateState* state = &ifuse_mem_gate_state[proc_id];
    if (state->initialized) {
        return;
    }

    memset(state, 0, sizeof(*state));
    state->initialized = TRUE;
    state->window_start_cycle = cycle_count;
}

static void ifuse_policy_update_window(uns proc_id) {
    IFuseMemGateState* state;
    Counter elapsed;
    Counter threshold;

    if (!IFUSE_ADAPTIVE_MEM_GATE) {
        return;
    }

    ifuse_policy_init_core(proc_id);
    state = &ifuse_mem_gate_state[proc_id];
    if (state->enabled) {
        return;
    }

    elapsed = cycle_count - state->window_start_cycle;
    if (elapsed < IFUSE_MEM_GATE_WINDOW_CYCLES) {
        return;
    }

    STAT_EVENT(proc_id, IFUSE_MEM_GATE_OBSERVED_WINDOWS);
    INC_STAT_EVENT(proc_id, IFUSE_MEM_GATE_TOTAL_CYCLES, elapsed);
    INC_STAT_EVENT(proc_id, IFUSE_MEM_GATE_DC_BLOCKED_CYCLES,
                   state->dc_blocked_cycles);

    threshold =
        (elapsed * (Counter)IFUSE_MEM_GATE_ENABLE_PERMILLE + 999U) / 1000U;
    if (state->dc_blocked_cycles >= threshold) {
        state->enabled = TRUE;
        STAT_EVENT(proc_id, IFUSE_MEM_GATE_ENABLE_EVENTS);
    } else {
        STAT_EVENT(proc_id, IFUSE_MEM_GATE_DISABLED_WINDOWS);
        state->window_start_cycle = cycle_count;
        state->dc_blocked_cycles = 0;
    }
}

Flag ifuse_policy_prediction_allowed(uns proc_id) {
    if (!IFUSE_ADAPTIVE_MEM_GATE) {
        return TRUE;
    }
    ifuse_policy_update_window(proc_id);
    return ifuse_mem_gate_state[proc_id].enabled;
}

void ifuse_policy_observe_dc_miss_blocked_cycle(uns proc_id) {
    if (!IFUSE_ADAPTIVE_MEM_GATE) {
        return;
    }
    ifuse_policy_init_core(proc_id);
    ifuse_mem_gate_state[proc_id].dc_blocked_cycles++;
    ifuse_policy_update_window(proc_id);
}
