#include "ifuse_train_retire.h"

#include "ifuse_retired_load_history.h"
#include "ifuse_training_table.h"
#include "ifuse.param.h"

#define IFUSE_TRAIN_CACHE_LINE_SIZE 64U

static uint64_t ifuse_retired_load_num = 0;

void ifuse_train_retire_init(void) {
    ifuse_retired_load_num = 0;
    retired_load_history_clear();
}

void ifuse_train_retired_op(Op* op) {
    if (!op || op->off_path || !op->inst_info) {
        return;
    }
    if (!IFUSE_ENABLED) {
        return;
    }

    if (op->inst_info->table_info.mem_type == MEM_ST &&
        op->oracle_info.va != 0) {
        // A retired store breaks a candidate pair if it overwrote the cache
        // block after an earlier retired load. Retire ordering matters here:
        // invalidating at fetch would act before the store becomes committed.
        Addr cacheblock_addr =
            op->oracle_info.va & ~(Addr)(IFUSE_TRAIN_CACHE_LINE_SIZE - 1U);
        retired_load_history_invalidate_cacheblock(cacheblock_addr);
        return;
    }

    if (op->inst_info->table_info.mem_type != MEM_LD ||
        op->oracle_info.va == 0 || op->oracle_info.mem_size == 0) {
        return;
    }

    // Fusion distance counts loads, not all micro-ops. Advance this sequence
    // for every valid retiring on-path load, including already-predicted loads.
    uint64_t current_load_num = ++ifuse_retired_load_num;

    // Predicted LOAD1/LOAD2 pairs are already resolved by frontend validation.
    // Discovery training scans ordinary retired loads only, avoiding duplicate
    // training observations for a pair that the FCT already predicted.
    if (op->ifuse_load_role != NOT_FUSION_CANDIDATE) {
        return;
    }

    RetiredLoadHistoryEntry matched_load;
    if (retired_load_history_find_and_remove_match(
            op->oracle_info.va, (unsigned int)op->op_num,
            current_load_num, &matched_load)) {
        // A prior retired load touched the same cache block, remained within
        // fusion distance, and was not invalidated by an intervening store.
        // Record the newly discovered LD1-to-LD2 pattern for FCT training.
        training_table_observe_fusible_pair(
            matched_load.load_pc_addr,
            op->inst_info->addr,
            matched_load.load_effective_addr,
            op->oracle_info.va,
            matched_load.load_memory_access_size,
            op->oracle_info.mem_size,
            matched_load.load_micro_op_num,
            (unsigned int)op->op_num,
            op->proc_id);
        return;
    }

    // No older fusible load was found. Keep this retiring load as a possible
    // LD1 for a later ordinary load.
    retired_load_history_insert(
        op->inst_info->addr,
        op->oracle_info.va,
        op->oracle_info.mem_size,
        (unsigned int)op->op_num,
        current_load_num);
}
