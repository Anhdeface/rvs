pub mod triage;
pub mod decompile;
pub mod flow;
pub mod xrefs;
pub mod patch_plan;
pub mod dynamic;

pub use triage::{run_triage, AgentTriageData, TriageFunctionSummary};
pub use decompile::{run_decompile, AgentDecompileData};
pub use flow::{run_flow, AgentFlowData, BranchGateNode};
pub use xrefs::{run_agent_xrefs, AgentXrefsData, CallerSummary, CalleeSummary, DataRefSummary};
pub use patch_plan::{run_patch_plan, AgentPatchPlanResult, PatchPlan, PatchPlanStep, PatchStepResult};
pub use dynamic::{run_agent_emulate, AgentEmulateData, AgentBranchOutcome};
