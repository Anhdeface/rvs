use clap::Parser;
use std::process::ExitCode;
use rvs::cli::{AgentCommands, AnalyzeCommands, Cli, Commands, DynamicCommands, GraphFormat, OutputFormat, PatchCommands};
use rvs::r2::R2Driver;
use rvs::response::{ApiError, ApiResponse, AppError};
use rvs::{agent, analysis, compact, patch};

fn make_compact_response<T: serde::Serialize>(
    command: impl Into<String>,
    target: impl Into<String>,
    data: T,
) -> ApiResponse<T> {
    let mut resp = ApiResponse::success(command, target, data);
    resp.format_version = None;
    resp.timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    resp
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::DisplayHelp
                || err.kind() == clap::error::ErrorKind::DisplayVersion
            {
                let _ = err.print();
                return ExitCode::SUCCESS;
            }

            let mut api_err = ApiError::new("INVALID_ARGUMENT", err.to_string());
            api_err.exit_code = Some(1);
            api_err.category = Some("INVALID_ARGUMENT".to_string());
            api_err.suggestion = Some("Run with '--help' to inspect valid CLI options and syntax.".to_string());

            let err_response = ApiResponse::error("rvs", "", api_err);
            if let Ok(json_output) = err_response.to_json(false) {
                println!("{json_output}");
            } else {
                eprintln!("{err}");
            }
            return ExitCode::from(1);
        }
    };

    let target_str = cli.file.as_ref().map(|f| f.display().to_string()).unwrap_or_default();
    let pretty = cli.pretty;

    let command_name = match &cli.command {
        Commands::Info => "info",
        Commands::Analyze(AnalyzeCommands::Functions { .. }) => "analyze functions",
        Commands::Analyze(AnalyzeCommands::Blocks { .. }) => "analyze blocks",
        Commands::Analyze(AnalyzeCommands::Graph { .. }) => "analyze graph",
        Commands::Analyze(AnalyzeCommands::PrologueEpilogue { .. }) => "analyze prologue-epilogue",
        Commands::Analyze(AnalyzeCommands::Xrefs { .. }) => "analyze xrefs",
        Commands::Patch(PatchCommands::Instruction { .. }) => "patch instruction",
        Commands::Patch(PatchCommands::String { .. }) => "patch string",
        Commands::Patch(PatchCommands::Bytes { .. }) => "patch bytes",
        Commands::Dynamic(DynamicCommands::Emulate { .. }) => "dynamic emulate",
        Commands::Dynamic(DynamicCommands::Trace { .. }) => "dynamic trace",
        Commands::Dynamic(DynamicCommands::Step { .. }) => "dynamic step",
        Commands::Strings { .. } => "strings",
        Commands::Symbols { .. } => "symbols",
        Commands::Agent(AgentCommands::Triage) => "agent triage",
        Commands::Agent(AgentCommands::Decompile { .. }) => "agent decompile",
        Commands::Agent(AgentCommands::Flow { .. }) => "agent flow",
        Commands::Agent(AgentCommands::Xrefs { .. }) => "agent xrefs",
        Commands::Agent(AgentCommands::PatchPlan { .. }) => "agent patch-plan",
        Commands::Agent(AgentCommands::Emulate { .. }) => "agent emulate",
        Commands::Agent(AgentCommands::Trace { .. }) => "agent trace",
    };

    match execute_cli(&cli, command_name, &target_str) {
        Ok(output) => {
            print!("{output}");
            if !output.ends_with('\n') {
                println!();
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let api_err = err.to_api_error();
            let exit_code = err.exit_code();
            let err_response = ApiResponse::error(command_name, target_str, api_err);
            if let Ok(json_output) = err_response.to_json(pretty) {
                println!("{json_output}");
            } else {
                eprintln!("Failed to serialize error response: {err}");
            }
            ExitCode::from(exit_code)
        }
    }
}

fn execute_cli(cli: &Cli, command_name: &str, target_str: &str) -> Result<String, AppError> {
    let file_path = cli.file.as_ref().ok_or_else(|| {
        AppError::InvalidArgument("Target binary file path is required. Use -f or --file <PATH>.".to_string())
    })?;

    // Pre-flight file validation
    if !file_path.exists() {
        return Err(AppError::FileNotFound(file_path.display().to_string()));
    }
    if file_path.is_dir() {
        return Err(AppError::FileNotFound(format!(
            "Target path is a directory, not a binary file: {}",
            file_path.display()
        )));
    }

    let metadata = std::fs::metadata(file_path)?;
    if metadata.len() == 0 {
        return Err(AppError::ZeroByteFile(file_path.display().to_string()));
    }

    let mut driver = R2Driver::new(file_path, cli.arch.clone(), cli.bits, cli.quiet)?;
    if let Some(secs) = cli.timeout {
        driver = driver.with_timeout(std::time::Duration::from_secs(secs));
    }
    let pretty = cli.pretty;
    let format = cli.format;
    let compact_flag = cli.compact || format == OutputFormat::Agent;

    match &cli.command {
        Commands::Info => {
            let data = analysis::get_binary_info(&driver)?;
            match format {
                OutputFormat::Markdown => Ok(format!(
                    "| Property | Value |\n|---|---|\n| Format | {} |\n| Architecture | {} |\n| Bitness | {} |\n| Endianness | {} |\n| Entry Point | {} |\n| Canary | {} |\n| NX | {} |\n| PIC | {} |\n| Stripped | {} |\n",
                    data.format,
                    data.arch,
                    data.bits,
                    data.endian,
                    data.entry_point_hex,
                    data.security.canary,
                    data.security.nx,
                    data.security.pic,
                    data.security.stripped,
                )),
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                OutputFormat::Agent => {
                    let comp = compact::CompactBinaryInfo::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactBinaryInfo::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Functions { filter, detail }) => {
            let data = analysis::analyze_functions(&driver, filter.as_deref(), *detail)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactFunctionsResponse::from_response(&data, *detail);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for f in &data.functions {
                        lines.push(serde_json::to_string(f)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Function | Offset (Hex) | Size | Complexity | Basic Blocks |\n|---|---|---|---|---|\n");
                    for f in &data.functions {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            f.name,
                            f.offset_hex,
                            f.size,
                            f.cyclomatic_complexity.unwrap_or(0),
                            f.num_basic_blocks.unwrap_or(0),
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactFunctionsResponse::from_response(&data, *detail);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Blocks { target, disasm }) => {
            let data = analysis::analyze_blocks(&driver, target, *disasm)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactBlocksResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for b in &data.blocks {
                        lines.push(serde_json::to_string(b)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Block Address | Size | Jump Target | Fail Target | Instructions |\n|---|---|---|---|---|\n");
                    for b in &data.blocks {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            b.addr_hex,
                            b.size,
                            b.jump_hex.as_deref().unwrap_or("-"),
                            b.fail_hex.as_deref().unwrap_or("-"),
                            b.num_instructions,
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactBlocksResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Graph { target, graph_type }) => {
            let graph_format = GraphFormat::from(format);
            let data = analysis::analyze_graph(&driver, target.as_deref(), *graph_type, graph_format)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactGraphResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactGraphResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::PrologueEpilogue { target }) => {
            let data = analysis::analyze_prologue_epilogue(&driver, target.as_deref())?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactPrologueEpilogueResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for f in &data.functions {
                        lines.push(serde_json::to_string(f)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Function | Address | Prologue | Epilogue |\n|---|---|---|---|\n");
                    for f in &data.functions {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} |\n",
                            f.name,
                            f.addr_hex,
                            if f.prologue.as_ref().map(|p| p.detected).unwrap_or(false) { "Yes" } else { "No" },
                            if f.epilogue.as_ref().map(|e| e.detected).unwrap_or(false) { "Yes" } else { "No" },
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactPrologueEpilogueResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Xrefs { target, xref_type, kind }) => {
            let data = analysis::analyze_xrefs(&driver, target, *xref_type, *kind)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactXrefsResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for x in &data.xrefs_to {
                        lines.push(serde_json::to_string(x)?);
                    }
                    for x in &data.xrefs_from {
                        lines.push(serde_json::to_string(x)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Type | Direction | From | To | To Function | Opcode |\n|---|---|---|---|---|---|\n");
                    for x in &data.xrefs_to {
                        md.push_str(&format!(
                            "| {} | TO | {} | {} | {} | {} |\n",
                            x.xref_type,
                            x.from_addr_hex,
                            x.to_addr_hex,
                            x.to_function.as_deref().unwrap_or(""),
                            x.opcode.as_deref().unwrap_or(""),
                        ));
                    }
                    for x in &data.xrefs_from {
                        md.push_str(&format!(
                            "| {} | FROM | {} | {} | {} | {} |\n",
                            x.xref_type,
                            x.from_addr_hex,
                            x.to_addr_hex,
                            x.to_function.as_deref().unwrap_or(""),
                            x.opcode.as_deref().unwrap_or(""),
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactXrefsResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Patch(PatchCommands::Instruction { addr, assembly, nop_bytes, backup }) => {
            let data = patch::patch_instruction(&driver, addr, assembly.as_deref(), *nop_bytes, *backup)?;
            let resp = ApiResponse::success(command_name, target_str, data);
            resp.to_json(pretty).map_err(Into::into)
        }

        Commands::Patch(PatchCommands::String { addr, old_string, new_string, pad_null, strict_length, backup }) => {
            let data = patch::patch_string(&driver, addr.as_deref(), old_string.as_deref(), new_string, *pad_null, *strict_length, *backup)?;
            let resp = ApiResponse::success(command_name, target_str, data);
            resp.to_json(pretty).map_err(Into::into)
        }

        Commands::Patch(PatchCommands::Bytes { addr, hex_bytes, backup }) => {
            let data = patch::patch_bytes(&driver, addr, hex_bytes, *backup)?;
            let resp = ApiResponse::success(command_name, target_str, data);
            resp.to_json(pretty).map_err(Into::into)
        }

        Commands::Strings { min_len } => {
            let data = analysis::list_strings(&driver, *min_len)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactStringsResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for s in &data.strings {
                        lines.push(serde_json::to_string(s)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Address | Length | String |\n|---|---|---|\n");
                    for s in &data.strings {
                        md.push_str(&format!(
                            "| {} | {} | {} |\n",
                            s.vaddr_hex,
                            s.size,
                            s.string,
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactStringsResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Symbols { filter } => {
            let data = analysis::list_symbols(&driver, filter.as_deref())?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactSymbolsResponse::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for s in &data.symbols {
                        lines.push(serde_json::to_string(s)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Markdown => {
                    let mut md = String::from("| Symbol | Address | Size | Type | Binding |\n|---|---|---|---|---|\n");
                    for s in &data.symbols {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            s.name,
                            s.vaddr_hex,
                            s.size,
                            s.sym_type,
                            s.bind,
                        ));
                    }
                    Ok(md)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactSymbolsResponse::from(data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        // Composite Agent subcommands
        Commands::Agent(AgentCommands::Triage) => {
            let data = agent::run_triage(&driver)?;
            match format {
                OutputFormat::Markdown => {
                    let mut md = format!(
                        "## Binary Triage: {}\n\n| Property | Value |\n|---|---|\n| Format | {} |\n| Architecture | {} |\n| Bitness | {} |\n| Endianness | {} |\n| Functions | {} |\n| Strings | {} |\n\n### Top Functions\n| Function | Address | Complexity | Blocks |\n|---|---|---|---|\n",
                        target_str, data.format, data.arch, data.bits, data.endian, data.total_functions, data.total_strings
                    );
                    for f in &data.top_functions {
                        md.push_str(&format!("| {} | {} | {} | {} |\n", f.name, f.addr_hex, f.complexity.unwrap_or(0), f.num_blocks.unwrap_or(0)));
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                OutputFormat::Agent => {
                    let comp = compact::CompactAgentTriageData::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentTriageData::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::Decompile { function }) => {
            let data = agent::run_decompile(&driver, function)?;
            match format {
                OutputFormat::Markdown => Ok(format!(
                    "### Pseudo-C Decompilation for `{}` ({})\n\n```c\n{}\n```\n",
                    data.function_name, data.function_addr_hex, data.pseudo_c
                )),
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                _ => {
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::Flow { function }) => {
            let data = agent::run_flow(&driver, function)?;
            match format {
                OutputFormat::Markdown => {
                    let mut md = format!(
                        "### Flow Analysis for `{}` ({})\nTotal Blocks: {}, Loops: {}\n\n| Decision Node | Condition | Branch | Jump Target | Fail Target |\n|---|---|---|---|---|\n",
                        data.function_name, data.function_addr_hex, data.total_blocks, data.loop_count
                    );
                    for n in &data.decision_nodes {
                        md.push_str(&format!(
                            "| {} | {} | {} | {} | {} |\n",
                            n.addr_hex, n.condition_instruction, n.branch_instruction, n.jump_target_hex, n.fail_target_hex
                        ));
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for n in &data.decision_nodes {
                        lines.push(serde_json::to_string(n)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Agent => {
                    let comp = compact::CompactAgentFlowData::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentFlowData::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::Xrefs { target }) => {
            let data = agent::run_agent_xrefs(&driver, target)?;
            match format {
                OutputFormat::Markdown => {
                    let mut md = format!("### Cross References for `{}`\n\n#### Callers\n| Function | Call Site |\n|---|---|\n", data.target);
                    for c in &data.callers {
                        md.push_str(&format!("| {} | {} |\n", c.function, c.call_site_hex));
                    }
                    md.push_str("\n#### Callees\n| Function | Call Site |\n|---|---|\n");
                    for c in &data.callees {
                        md.push_str(&format!("| {} | {} |\n", c.function, c.call_site_hex));
                    }
                    md.push_str("\n#### Data References\n| Address | Type | Preview |\n|---|---|---|\n");
                    for d in &data.data_refs {
                        md.push_str(&format!("| {} | {} | {} |\n", d.addr_hex, d.ref_type, d.value_preview.as_deref().unwrap_or("")));
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for c in &data.callers {
                        lines.push(serde_json::to_string(c)?);
                    }
                    for c in &data.callees {
                        lines.push(serde_json::to_string(c)?);
                    }
                    for d in &data.data_refs {
                        lines.push(serde_json::to_string(d)?);
                    }
                    Ok(lines.join("\n"))
                }
                OutputFormat::Agent => {
                    let comp = compact::CompactAgentXrefsData::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentXrefsData::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::PatchPlan { plan }) => {
            let data = agent::run_patch_plan(&driver, plan)?;
            let resp = ApiResponse::success(command_name, target_str, data);
            resp.to_json(pretty).map_err(Into::into)
        }

        Commands::Dynamic(DynamicCommands::Emulate {
            target,
            steps,
            until,
            reg_set,
            read_mem,
            mem_len,
        }) => {
            let opts = analysis::EmulateOptions {
                target: target.clone(),
                steps: *steps,
                until: until.clone(),
                reg_set: reg_set.clone(),
                read_mem: read_mem.clone(),
                mem_len: *mem_len,
                include_initial_regs: !compact_flag && format != OutputFormat::Agent,
            };
            let data = analysis::analyze_emulate(&driver, &opts)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactDynamicEmulateResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Markdown => {
                    let mut md = format!(
                        "### Dynamic Emulation: `{}`\n\n| Property | Value |\n|---|---|\n| Start Address | {} |\n| Final Address | {} |\n| Steps Executed | {} |\n| Stop Reason | {} |\n",
                        data.target, data.start_addr_hex, data.final_addr_hex, data.steps_executed, data.stop_reason
                    );
                    if let Some(ref ret) = data.return_value {
                        md.push_str(&format!("| Return Register | {} ({}) |\n", ret.reg.to_uppercase(), ret.value_hex));
                    }
                    if !data.register_diff.is_empty() {
                        md.push_str("\n#### Register Modifications\n| Register | Before | After |\n|---|---|---|\n");
                        for d in &data.register_diff {
                            md.push_str(&format!("| {} | {} | {} |\n", d.reg, d.before_hex, d.after_hex));
                        }
                    }
                    if let (Some(b), Some(a)) = (&data.memory_before, &data.memory_after) {
                        md.push_str(&format!("\n#### Memory Dump\nBefore: `{}`\nAfter:  `{}`\n", b, a));
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                _ => {
                    if compact_flag {
                        let comp = compact::CompactDynamicEmulateResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Dynamic(DynamicCommands::Trace {
            target,
            steps,
            reg_set,
        }) => {
            let opts = analysis::TraceOptions {
                target: target.clone(),
                steps: *steps,
                reg_set: reg_set.clone(),
            };
            let data = analysis::analyze_trace(&driver, &opts)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactDynamicTraceResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Markdown => {
                    let mut md = format!(
                        "### Dynamic Trace: `{}` ({} steps)\n\n| Step | Address | Disassembly | Register Changes |\n|---|---|---|---|\n",
                        data.target, data.total_steps
                    );
                    for s in &data.trace {
                        let diff_str = if s.reg_changes.is_empty() {
                            "-".to_string()
                        } else {
                            s.reg_changes
                                .iter()
                                .map(|d| format!("{}: {}->{}", d.reg, d.before_hex, d.after_hex))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        md.push_str(&format!("| {} | {} | `{}` | {} |\n", s.step, s.addr_hex, s.disasm, diff_str));
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => {
                    let mut lines = Vec::new();
                    for s in &data.trace {
                        lines.push(serde_json::to_string(s)?);
                    }
                    Ok(lines.join("\n"))
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactDynamicTraceResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Dynamic(DynamicCommands::Step {
            target,
            count,
            reg_set,
        }) => {
            let data = analysis::analyze_step(&driver, target, *count, reg_set)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactDynamicStepResponse::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                OutputFormat::Markdown => {
                    let diff_str = if data.reg_changes.is_empty() {
                        "-".to_string()
                    } else {
                        data.reg_changes
                            .iter()
                            .map(|d| format!("{}: {} -> {}", d.reg, d.before_hex, d.after_hex))
                            .collect::<Vec<_>>()
                            .join(", ")
                    };
                    Ok(format!(
                        "### Step `{}` -> `{}`\n- Instruction: `{}`\n- Register Changes: {}\n",
                        data.current_addr_hex, data.next_addr_hex, data.instruction, diff_str
                    ))
                }
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                _ => {
                    if compact_flag {
                        let comp = compact::CompactDynamicStepResponse::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::Emulate {
            target,
            steps,
            until,
            reg,
            read_mem,
            mem_len,
        }) => {
            let data = agent::run_agent_emulate(
                &driver,
                target,
                *steps,
                until.clone(),
                reg.clone(),
                read_mem.clone(),
                *mem_len,
            )?;
            match format {
                OutputFormat::Markdown => {
                    let mut md = format!(
                        "### Agent Dynamic Emulation: `{}`\n> {}\n\n| Property | Value |\n|---|---|\n| Start | {} |\n| Final | {} |\n| Steps | {} |\n| Reason | {} |\n",
                        data.function_name, data.agent_summary, data.start_addr_hex, data.final_addr_hex, data.steps_executed, data.stop_reason
                    );
                    if let Some(ref ret) = data.return_value {
                        md.push_str(&format!("| Return Value | {} ({}) |\n", ret.reg.to_uppercase(), ret.value_hex));
                    }
                    if !data.branches_encountered.is_empty() {
                        md.push_str("\n#### Resolved Decision Branch Gates\n| Gate | Condition | Branch | Taken | Target |\n|---|---|---|---|---|\n");
                        for b in &data.branches_encountered {
                            md.push_str(&format!(
                                "| {} | {} | {} | {} | {} |\n",
                                b.gate_addr_hex, b.condition_instruction, b.branch_instruction, if b.taken { "YES" } else { "NO" }, b.target_addr_hex
                            ));
                        }
                    }
                    if !data.key_registers_changed.is_empty() {
                        md.push_str("\n#### Key Register Modifications\n| Register | Before | After |\n|---|---|---|\n");
                        for d in &data.key_registers_changed {
                            md.push_str(&format!("| {} | {} | {} |\n", d.reg, d.before_hex, d.after_hex));
                        }
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                OutputFormat::Agent => {
                    let comp = compact::CompactAgentEmulateData::from(&data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentEmulateData::from(&data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Agent(AgentCommands::Trace {
            target,
            steps,
            reg,
        }) => {
            let opts = analysis::TraceOptions {
                target: target.clone(),
                steps: *steps,
                reg_set: reg.clone(),
            };
            let data = analysis::analyze_trace(&driver, &opts)?;
            if compact_flag {
                let comp = compact::CompactDynamicTraceResponse::from(&data);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                match format {
                    OutputFormat::Jsonl => {
                        let mut lines = Vec::new();
                        for s in &data.trace {
                            lines.push(serde_json::to_string(s)?);
                        }
                        Ok(lines.join("\n"))
                    }
                    _ => {
                        let resp = ApiResponse::success(command_name, target_str, data);
                        resp.to_json(pretty).map_err(Into::into)
                    }
                }
            }
        }
    }
}
