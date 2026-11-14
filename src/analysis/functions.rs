use serde::{Deserialize, Serialize};
use crate::r2::R2Driver;
use crate::response::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionsResponse {
    pub count: usize,
    pub functions: Vec<FunctionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FunctionInfo {
    pub name: String,
    pub offset: u64,
    pub offset_hex: String,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calltype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cyclomatic_complexity: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_basic_blocks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_instructions: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_pure: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_args: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_locals: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_frame_size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawR2Function {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    addr: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    realsz: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    calltype: Option<String>,
    #[serde(default)]
    cc: Option<u64>,
    #[serde(default)]
    cost: Option<u64>,
    #[serde(default)]
    nbbs: Option<u64>,
    #[serde(default)]
    ninstrs: Option<u64>,
    #[serde(default, rename = "is-pure")]
    is_pure: Option<serde_json::Value>,
    #[serde(default)]
    nargs: Option<u64>,
    #[serde(default)]
    nlocals: Option<u64>,
    #[serde(default)]
    stackframe: Option<u64>,
}

pub fn analyze_functions(
    driver: &R2Driver,
    filter: Option<&str>,
    detail: bool,
) -> Result<FunctionsResponse, AppError> {
    let cmd = if driver.is_aarch64() { "aaa; aflj" } else { "aa; aflj" };
    let raw_funcs: Vec<RawR2Function> = driver.cmdj(cmd)?;

    let mut functions = Vec::with_capacity(raw_funcs.len());

    for f in raw_funcs {
        let name_str = f.name.as_deref().unwrap_or("unknown");

        if let Some(f_pat) = filter {
            if !name_str.contains(f_pat) {
                continue;
            }
        }

        let name = f.name.unwrap_or_else(|| "unknown".to_string());
        let offset = f.offset.or(f.addr).unwrap_or(0);
        let size = f.size.or(f.realsz).unwrap_or(0);
        let signature = f.signature;
        let calltype = f.calltype;
        let cyclomatic_complexity = f.cc.or(f.cost);
        let num_basic_blocks = f.nbbs;
        let num_instructions = f.ninstrs;

        let is_pure = f.is_pure.as_ref().and_then(|v| {
            if let Some(b) = v.as_bool() {
                Some(b)
            } else {
                v.as_str().map(|s| s == "true")
            }
        });

        let num_args = f.nargs;
        let num_locals = f.nlocals;
        let stack_frame_size = if detail { f.stackframe } else { None };

        let func_info = FunctionInfo {
            name,
            offset,
            offset_hex: format!("{:#x}", offset),
            size,
            signature,
            calltype,
            cyclomatic_complexity,
            num_basic_blocks,
            num_instructions,
            is_pure,
            num_args,
            num_locals,
            stack_frame_size,
        };

        functions.push(func_info);
    }

    Ok(FunctionsResponse {
        count: functions.len(),
        functions,
    })
}
