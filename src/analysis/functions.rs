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

pub fn analyze_functions(
    driver: &R2Driver,
    filter: Option<&str>,
    detail: bool,
) -> Result<FunctionsResponse, AppError> {
    let raw_funcs: Vec<serde_json::Value> = driver.cmdj("aa; aflj")?;


    let mut functions = Vec::new();

    for f in raw_funcs {
        let name = f.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if let Some(f_pat) = filter {
            if !name.contains(f_pat) {
                continue;
            }
        }

        let offset = f.get("offset")
            .or_else(|| f.get("addr"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let size = f.get("size")
            .or_else(|| f.get("realsz"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let signature = f.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string());
        let calltype = f.get("calltype").and_then(|v| v.as_str()).map(|s| s.to_string());
        let cyclomatic_complexity = f.get("cc").or_else(|| f.get("cost")).and_then(|v| v.as_u64());
        let num_basic_blocks = f.get("nbbs").and_then(|v| v.as_u64());
        let num_instructions = f.get("ninstrs").and_then(|v| v.as_u64());
        
        let is_pure = f.get("is-pure")
            .and_then(|v| {
                if let Some(b) = v.as_bool() {
                    Some(b)
                } else {
                    v.as_str().map(|s| s == "true")
                }
            });

        let num_args = f.get("nargs").and_then(|v| v.as_u64());
        let num_locals = f.get("nlocals").and_then(|v| v.as_u64());
        let stack_frame_size = f.get("stackframe").and_then(|v| v.as_u64());

        let func_info = if detail {
            FunctionInfo {
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
            }
        } else {
            FunctionInfo {
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
                stack_frame_size: None,
            }
        };

        functions.push(func_info);
    }

    Ok(FunctionsResponse {
        count: functions.len(),
        functions,
    })
}
