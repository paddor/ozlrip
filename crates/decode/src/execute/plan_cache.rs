use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use crate::parse::FramePlan;

use super::{ChunkExecutionPlan, build_chunk_execution_plan, direct_append_tail};

#[derive(Clone)]
pub(crate) struct DirectAppendChunkPlans {
    pub(super) chunk_plans: Vec<Option<ChunkExecutionPlan>>,
}

pub(crate) struct ChunkExecutionPlans {
    pub(super) chunk_plans: Vec<Option<ChunkExecutionPlan>>,
}

pub(crate) fn prepare_chunk_execution_plans(plan: &FramePlan) -> Result<ChunkExecutionPlans> {
    let mut chunk_plans = Vec::new();
    chunk_plans
        .try_reserve_exact(plan.chunks.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("chunk execution plan allocation failed")
        })?;
    for chunk in &plan.chunks {
        if chunk.has_nodes() {
            chunk_plans.push(Some(build_chunk_execution_plan(chunk)?));
        } else {
            chunk_plans.push(None);
        }
    }
    Ok(ChunkExecutionPlans { chunk_plans })
}

pub(crate) fn prepare_direct_append_chunk_plans(
    plan: &FramePlan,
) -> Result<Option<DirectAppendChunkPlans>> {
    let mut chunk_plans = Vec::new();
    let mut has_direct_append_chunk = false;
    chunk_plans
        .try_reserve_exact(plan.chunks.len())
        .map_err(|_| {
            Error::new(ErrorKind::LimitExceeded)
                .with_detail("chunk execution plan allocation failed")
        })?;
    for chunk in &plan.chunks {
        if !chunk.has_nodes() {
            chunk_plans.push(None);
            continue;
        }
        let Ok(chunk_plan) = build_chunk_execution_plan(chunk) else {
            chunk_plans.push(None);
            continue;
        };
        if direct_append_tail(&chunk_plan).is_some() {
            has_direct_append_chunk = true;
            chunk_plans.push(Some(chunk_plan));
        } else {
            chunk_plans.push(None);
        }
    }
    if has_direct_append_chunk {
        Ok(Some(DirectAppendChunkPlans { chunk_plans }))
    } else {
        Ok(None)
    }
}
