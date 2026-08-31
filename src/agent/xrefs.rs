use serde::{Deserialize, Serialize};
use crate::analysis::{self, xrefs::XrefDirection};
use crate::error::AppError;
use crate::r2::R2Driver;

/// Payload for `agent xrefs` command
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentXrefsData {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_addr_hex: Option<String>,
    pub callers: Vec<CallerSummary>,
    pub callees: Vec<CalleeSummary>,
    pub data_refs: Vec<DataRefSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallerSummary {
    pub function: String,
    pub call_site: u64,
    pub call_site_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CalleeSummary {
    pub function: String,
    pub call_site: u64,
    pub call_site_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataRefSummary {
    pub addr: u64,
    pub addr_hex: String,
    pub ref_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_preview: Option<String>,
}

pub fn run_agent_xrefs(driver: &R2Driver, target: &str) -> Result<AgentXrefsData, AppError> {
    let xrefs_resp = analysis::analyze_xrefs(driver, target, XrefDirection::All, None)?;

    let mut callers = Vec::new();
    let mut callees = Vec::new();
    let mut data_refs = Vec::new();

    let mut seen_caller_sites = std::collections::HashSet::new();
    let mut seen_callee_sites = std::collections::HashSet::new();
    let mut seen_data_addrs = std::collections::HashSet::new();

    for x in &xrefs_resp.xrefs_to {
        let type_lower = x.xref_type.to_lowercase();
        if type_lower.contains("call") {
            if seen_caller_sites.insert(x.from_addr) {
                callers.push(CallerSummary {
                    function: x
                        .from_function
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", x.from_addr)),
                    call_site: x.from_addr,
                    call_site_hex: format!("0x{:x}", x.from_addr),
                });
            }
        } else if seen_data_addrs.insert((x.from_addr, x.xref_type.clone())) {
            data_refs.push(DataRefSummary {
                addr: x.from_addr,
                addr_hex: format!("0x{:x}", x.from_addr),
                ref_type: x.xref_type.clone(),
                value_preview: x.opcode.clone(),
            });
        }
    }

    for x in &xrefs_resp.xrefs_from {
        let type_lower = x.xref_type.to_lowercase();
        if type_lower.contains("call") {
            let key = (x.from_addr, x.to_addr);
            if seen_callee_sites.insert(key) {
                callees.push(CalleeSummary {
                    function: x
                        .to_function
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", x.to_addr)),
                    call_site: x.from_addr,
                    call_site_hex: format!("0x{:x}", x.from_addr),
                });
            }
        } else if seen_data_addrs.insert((x.to_addr, x.xref_type.clone())) {
            data_refs.push(DataRefSummary {
                addr: x.to_addr,
                addr_hex: format!("0x{:x}", x.to_addr),
                ref_type: x.xref_type.clone(),
                value_preview: x.opcode.clone(),
            });
        }
    }

    Ok(AgentXrefsData {
        target: xrefs_resp.target,
        target_addr: Some(xrefs_resp.target_addr),
        target_addr_hex: Some(xrefs_resp.target_addr_hex),
        callers,
        callees,
        data_refs,
    })
}
