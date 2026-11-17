use clap::Parser;
use std::process::ExitCode;
use rvs::cli::{AgentCommands, AnalyzeCommands, ApkCommands, Cli, Commands, DebugCommands, DynamicCommands, FridaCommands, GraphFormat, OutputFormat, PatchCommands};
use rvs::r2::R2Driver;
use rvs::response::{ApiError, ApiResponse, AppError};
use rvs::apk::{ApkPackage, ApkSource, ManifestInfo};
use rvs::{agent, analysis, apk, compact, debug, frida, patch};

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

struct TempFileGuard(Option<std::path::PathBuf>);
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
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

    let target_str = match &cli.command {
        Commands::Dynamic(DynamicCommands::Debug(dbg_cmd)) => match dbg_cmd {
            DebugCommands::Spawn { file, .. } => file
                .as_ref()
                .map(|f| f.display().to_string())
                .or_else(|| cli.file.as_ref().map(|f| f.display().to_string()))
                .unwrap_or_default(),
            DebugCommands::Attach { pid } => format!("pid:{pid}"),
            DebugCommands::Continue { session_id, session, .. }
            | DebugCommands::Step { session_id, session, .. }
            | DebugCommands::Breakpoint { session_id, session, .. }
            | DebugCommands::Registers { session_id, session, .. }
            | DebugCommands::Memory { session_id, session, .. }
            | DebugCommands::Kill { session_id, session } => {
                session.as_deref().or(session_id.as_deref()).unwrap_or_default().to_string()
            }
            DebugCommands::ListSessions | DebugCommands::Daemon { .. } => "daemon".to_string(),
        },
        Commands::Frida(frida_cmd) => match frida_cmd {
            FridaCommands::EnvCheck => "host".to_string(),
            FridaCommands::Attach { target, .. } => target.clone(),
            FridaCommands::Spawn { path, .. } => path.display().to_string(),
            FridaCommands::Modules { target, .. }
            | FridaCommands::Symbols { target, .. }
            | FridaCommands::Classes { target, .. }
            | FridaCommands::Hook { target, .. }
            | FridaCommands::TraceRegs { target, .. }
            | FridaCommands::HookReturn { target, .. }
            | FridaCommands::HooksList { target, .. }
            | FridaCommands::HookRemove { target, .. }
            | FridaCommands::Script { target, .. }
            | FridaCommands::Rpc { target, .. }
            | FridaCommands::MemRead { target, .. }
            | FridaCommands::MemWrite { target, .. } => target.clone(),
        },
        Commands::Apk(apk_cmd) => match apk_cmd {
            ApkCommands::Inspect { path }
            | ApkCommands::Manifest { path, .. }
            | ApkCommands::Dex { path, .. }
            | ApkCommands::So { path, .. }
            | ApkCommands::Resources { path, .. }
            | ApkCommands::Signature { path, .. } => path.display().to_string(),
        },
        _ => cli.file.as_ref().map(|f| f.display().to_string()).unwrap_or_default(),
    };
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
        Commands::Dynamic(DynamicCommands::Debug(dbg_cmd)) => match dbg_cmd {
            DebugCommands::Spawn { .. } => "dynamic debug spawn",
            DebugCommands::Attach { .. } => "dynamic debug attach",
            DebugCommands::Continue { .. } => "dynamic debug continue",
            DebugCommands::Step { .. } => "dynamic debug step",
            DebugCommands::Breakpoint { .. } => "dynamic debug breakpoint",
            DebugCommands::Registers { .. } => "dynamic debug registers",
            DebugCommands::Memory { .. } => "dynamic debug memory",
            DebugCommands::Kill { .. } => "dynamic debug kill",
            DebugCommands::ListSessions => "dynamic debug list-sessions",
            DebugCommands::Daemon { .. } => "dynamic debug daemon",
        },
        Commands::Strings { .. } => "strings",
        Commands::Symbols { .. } => "symbols",
        Commands::Agent(AgentCommands::Triage) => "agent triage",
        Commands::Agent(AgentCommands::Decompile { .. }) => "agent decompile",
        Commands::Agent(AgentCommands::Flow { .. }) => "agent flow",
        Commands::Agent(AgentCommands::Xrefs { .. }) => "agent xrefs",
        Commands::Agent(AgentCommands::PatchPlan { .. }) => "agent patch-plan",
        Commands::Agent(AgentCommands::Emulate { .. }) => "agent emulate",
        Commands::Agent(AgentCommands::Trace { .. }) => "agent trace",
        Commands::Frida(frida_cmd) => match frida_cmd {
            FridaCommands::EnvCheck => "frida env-check",
            FridaCommands::Attach { .. } => "frida attach",
            FridaCommands::Spawn { .. } => "frida spawn",
            FridaCommands::Modules { .. } => "frida modules",
            FridaCommands::Symbols { .. } => "frida symbols",
            FridaCommands::Classes { .. } => "frida classes",
            FridaCommands::Hook { .. } => "frida hook",
            FridaCommands::TraceRegs { .. } => "frida trace-regs",
            FridaCommands::HookReturn { .. } => "frida hook-return",
            FridaCommands::HooksList { .. } => "frida hooks-list",
            FridaCommands::HookRemove { .. } => "frida hook-remove",
            FridaCommands::Script { .. } => "frida script",
            FridaCommands::Rpc { .. } => "frida rpc",
            FridaCommands::MemRead { .. } => "frida mem-read",
            FridaCommands::MemWrite { .. } => "frida mem-write",
        },
        Commands::Apk(ApkCommands::Inspect { .. }) => "apk inspect",
        Commands::Apk(ApkCommands::Manifest { .. }) => "apk manifest",
        Commands::Apk(ApkCommands::Dex { .. }) => "apk dex",
        Commands::Apk(ApkCommands::So { .. }) => "apk so",
        Commands::Apk(ApkCommands::Resources { .. }) => "apk resources",
        Commands::Apk(ApkCommands::Signature { .. }) => "apk signature",
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
    if let Commands::Dynamic(DynamicCommands::Debug(dbg_cmd)) = &cli.command {
        return debug::handle_debug_command(cli, dbg_cmd);
    }
    if let Commands::Frida(frida_cmd) = &cli.command {
        return frida::handle_frida_command(cli, frida_cmd);
    }
    if let Commands::Apk(apk_cmd) = &cli.command {
        return handle_apk_command(cli, apk_cmd, command_name, target_str);
    }
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
                    let comp = compact::CompactBinaryInfo::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactBinaryInfo::from(data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Functions { filter, detail, format: cmd_format }) => {
            let format = cmd_format.unwrap_or(format);
            let compact_flag = cli.compact || format == OutputFormat::Agent;
            let data = analysis::analyze_functions(&driver, filter.as_deref(), *detail)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactFunctionsResponse::from_response_owned(data, *detail);
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
                        let comp = compact::CompactFunctionsResponse::from_response_owned(data, *detail);
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
                    let comp = compact::CompactBlocksResponse::from(data);
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
                        let comp = compact::CompactBlocksResponse::from(data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Graph { target, graph_type, format: cmd_format }) => {
            let format = cmd_format.unwrap_or(format);
            let compact_flag = cli.compact || format == OutputFormat::Agent;
            let graph_format = GraphFormat::from(format);
            let data = analysis::analyze_graph(&driver, target.as_deref(), *graph_type, graph_format)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactGraphResponse::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactGraphResponse::from(data);
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
                    let comp = compact::CompactPrologueEpilogueResponse::from(data);
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
                        let comp = compact::CompactPrologueEpilogueResponse::from(data);
                        let resp = make_compact_response(command_name, target_str, comp);
                        return resp.to_json(pretty).map_err(Into::into);
                    }
                    let resp = ApiResponse::success(command_name, target_str, data);
                    resp.to_json(pretty).map_err(Into::into)
                }
            }
        }

        Commands::Analyze(AnalyzeCommands::Xrefs { target, xref_type, kind, format: cmd_format }) => {
            let format = cmd_format.unwrap_or(format);
            let compact_flag = cli.compact || format == OutputFormat::Agent;
            let data = analysis::analyze_xrefs(&driver, target, *xref_type, *kind)?;
            match format {
                OutputFormat::Agent => {
                    let comp = compact::CompactXrefsResponse::from(data);
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
                        let comp = compact::CompactXrefsResponse::from(data);
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
                    let comp = compact::CompactStringsResponse::from(data);
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
                        let comp = compact::CompactStringsResponse::from(data);
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
                    if let Some(ref langs) = data.detected_languages {
                        if !langs.is_empty() {
                            md.push_str("\n### Detected Languages & Frameworks\n| Language | Confidence | Evidence |\n|---|---|---|\n");
                            for l in langs {
                                md.push_str(&format!("| {} | {} | {} |\n", l.language, l.confidence, l.evidence.join("; ")));
                            }
                        }
                    }
                    Ok(md)
                }
                OutputFormat::Jsonl => serde_json::to_string(&data).map_err(Into::into),
                OutputFormat::Agent => {
                    let comp = compact::CompactAgentTriageData::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentTriageData::from(data);
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
                    let comp = compact::CompactAgentFlowData::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentFlowData::from(data);
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
                    let comp = compact::CompactAgentXrefsData::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentXrefsData::from(data);
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
                    let comp = compact::CompactDynamicEmulateResponse::from(data);
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
                        let comp = compact::CompactDynamicEmulateResponse::from(data);
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
                    let comp = compact::CompactDynamicTraceResponse::from(data);
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
                        let comp = compact::CompactDynamicTraceResponse::from(data);
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
                    let comp = compact::CompactDynamicStepResponse::from(data);
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
                        let comp = compact::CompactDynamicStepResponse::from(data);
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
                    let comp = compact::CompactAgentEmulateData::from(data);
                    let resp = make_compact_response(command_name, target_str, comp);
                    resp.to_json(pretty).map_err(Into::into)
                }
                _ => {
                    if compact_flag {
                        let comp = compact::CompactAgentEmulateData::from(data);
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
                let comp = compact::CompactDynamicTraceResponse::from(data);
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

        Commands::Dynamic(DynamicCommands::Debug(dbg_cmd)) => {
            debug::handle_debug_command(cli, dbg_cmd)
        }

        Commands::Frida(frida_cmd) => {
            frida::handle_frida_command(cli, frida_cmd)
        }

        Commands::Apk(apk_cmd) => {
            handle_apk_command(cli, apk_cmd, command_name, target_str)
        }
    }
}

fn handle_apk_command(
    cli: &Cli,
    apk_cmd: &ApkCommands,
    command_name: &str,
    target_str: &str,
) -> Result<String, AppError> {
    let pretty = cli.pretty;
    let format = cli.format;
    let compact_flag = cli.compact || format == OutputFormat::Agent;

    match apk_cmd {
        ApkCommands::Inspect { path } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let pkg = ApkPackage::open(path)?;

            // Validate that an unpacked directory contains Android artifacts
            if let ApkSource::Directory(_) = &pkg.source {
                if pkg.manifest_data.is_none() && pkg.dex_entries.is_empty() && pkg.native_libraries.is_empty() {
                    return Err(AppError::InvalidBinary(format!(
                        "Directory '{}' contains no Android artifacts (AndroidManifest.xml, DEX, or native libraries)",
                        path.display()
                    )));
                }
            }

            // Standalone validation
            if let ApkSource::Standalone(_) = &pkg.source {
                if !pkg.dex_entries.is_empty() {
                    let bytes = pkg.read_entry(&pkg.dex_entries[0].name)?;
                    apk::parse_dex_bytes(&bytes, &pkg.dex_entries[0].name)?;
                } else if !pkg.native_libraries.is_empty() {
                    let first_lib = pkg.native_libraries.values().flatten().next();
                    if let Some(entry) = first_lib {
                        let bytes = pkg.read_entry(&entry.name)?;
                        apk::parse_native_so_bytes(&bytes, &entry.name)?;
                    }
                }
            }

            let source_type = match &pkg.source {
                ApkSource::Archive(_) => "archive".to_string(),
                ApkSource::Directory(_) => "directory".to_string(),
                ApkSource::Standalone(_) => "standalone".to_string(),
            };

            let manifest = if let Some(data) = &pkg.manifest_data {
                Some(ManifestInfo::parse(data, pkg.is_manifest_binary)?)
            } else {
                None
            };

            let package_name = manifest.as_ref().map(|m| m.package_name.clone());
            let version_name = manifest.as_ref().and_then(|m| m.version_name.clone());
            let version_code = manifest.as_ref().and_then(|m| m.version_code);
            let has_manifest = manifest.is_some() || pkg.manifest_data.is_some();
            let is_manifest_binary = pkg.is_manifest_binary;

            let dex_files = pkg.dex_names();
            let mut native_libraries = std::collections::HashMap::new();
            for (abi, entries) in &pkg.native_libraries {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                native_libraries.insert(abi.clone(), names);
            }

            let languages = pkg.detect_languages();

            let data = compact::ApkInspectData {
                source_type,
                package_name,
                version_name,
                version_code,
                has_manifest,
                is_manifest_binary,
                dex_files,
                native_libraries,
                languages,
            };

            if compact_flag {
                let comp = compact::CompactApkInspectData::from(&data);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, data);
                resp.to_json(pretty).map_err(Into::into)
            }
        }

        ApkCommands::Manifest { path, raw } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let (bytes, is_binary) = if path.is_dir() {
                let pkg = ApkPackage::open(path)?;
                match pkg.manifest_data {
                    Some(d) => (d, pkg.is_manifest_binary),
                    None => {
                        return Err(AppError::FileNotFound(format!(
                            "AndroidManifest.xml not found in directory '{}'",
                            path.display()
                        )));
                    }
                }
            } else {
                let file_bytes = std::fs::read(path)?;
                let is_zip = file_bytes.len() >= 4 && (&file_bytes[..4] == b"PK\x03\x04" || &file_bytes[..4] == b"PK\x05\x06");
                if is_zip {
                    let pkg = ApkPackage::open(path)?;
                    match pkg.manifest_data {
                        Some(d) => (d, pkg.is_manifest_binary),
                        None => {
                            return Err(AppError::FileNotFound(format!(
                                "AndroidManifest.xml not found in APK '{}'",
                                path.display()
                            )));
                        }
                    }
                } else {
                    let binary_hint = path.extension().and_then(|s| s.to_str()) == Some("axml")
                        || apk::is_binary_axml(&file_bytes);
                    (file_bytes, binary_hint)
                }
            };

            let mut manifest = ManifestInfo::parse(&bytes, is_binary)?;
            if *raw {
                if let Ok(xml_str) = apk::decode_raw_manifest(&bytes) {
                    manifest.raw_xml = Some(xml_str);
                }
            }

            if compact_flag {
                let comp = compact::CompactManifestInfo::from(&manifest);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, manifest);
                resp.to_json(pretty).map_err(Into::into)
            }
        }

        ApkCommands::Dex {
            path,
            dex_file,
            class,
            method,
            disasm,
            smali,
            decompile,
        } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let file_bytes = if path.is_file() {
                Some(std::fs::read(path)?)
            } else {
                None
            };

            let is_archive_or_dir = path.is_dir() || file_bytes.as_ref().map(|b| {
                b.len() >= 4 && (&b[..4] == b"PK\x03\x04" || &b[..4] == b"PK\x05\x06")
            }).unwrap_or(false);

            let mut _temp_guard = TempFileGuard(None);
            let mut resolved_dex_path = path.to_path_buf();

            let mut analysis_result = if !is_archive_or_dir {
                let bytes = file_bytes.unwrap();
                apk::parse_dex_bytes(&bytes, &path.display().to_string())?
            } else {
                let pkg = ApkPackage::open(path)?;
                if pkg.dex_entries.is_empty() {
                    return Err(AppError::FileNotFound(format!(
                        "No DEX files found in '{}'",
                        path.display()
                    )));
                }

                if let Some(target_dex) = &dex_file {
                    let entry = pkg.dex_entries.iter().find(|e| {
                        e.name == *target_dex || e.name.ends_with(target_dex)
                    }).ok_or_else(|| {
                        AppError::FileNotFound(format!(
                            "DEX file '{}' not found in package",
                            target_dex
                        ))
                    })?;
                    if let Some(p) = &entry.path {
                        if p.is_file() {
                            resolved_dex_path = p.clone();
                        }
                    } else {
                        let bytes = pkg.read_entry(&entry.name)?;
                        let t_path = std::env::temp_dir().join(format!("rvs_dex_{}_{}.dex", std::process::id(), entry.name.replace('/', "_")));
                        std::fs::write(&t_path, &bytes)?;
                        resolved_dex_path = t_path.clone();
                        _temp_guard = TempFileGuard(Some(t_path));
                    }
                    let bytes = pkg.read_entry(&entry.name)?;
                    apk::parse_dex_bytes(&bytes, &entry.name)?
                } else if pkg.dex_entries.len() == 1 {
                    let entry = &pkg.dex_entries[0];
                    if let Some(p) = &entry.path {
                        if p.is_file() {
                            resolved_dex_path = p.clone();
                        }
                    } else {
                        let bytes = pkg.read_entry(&entry.name)?;
                        let t_path = std::env::temp_dir().join(format!("rvs_dex_{}_{}.dex", std::process::id(), entry.name.replace('/', "_")));
                        std::fs::write(&t_path, &bytes)?;
                        resolved_dex_path = t_path.clone();
                        _temp_guard = TempFileGuard(Some(t_path));
                    }
                    let bytes = pkg.read_entry(&entry.name)?;
                    apk::parse_dex_bytes(&bytes, &entry.name)?
                } else {
                    // Multi-DEX merge
                    let mut combined_classes = Vec::new();
                    let mut total_methods = 0;
                    let mut total_strings = 0;
                    let mut all_strings = Vec::new();

                    for entry in &pkg.dex_entries {
                        let bytes = pkg.read_entry(&entry.name)?;
                        let r = apk::parse_dex_bytes(&bytes, &entry.name)?;
                        total_methods += r.methods_count;
                        total_strings += r.strings_count;
                        if let Some(strs) = r.strings {
                            all_strings.extend(strs);
                        }
                        combined_classes.extend(r.classes);
                    }

                    // For multi-DEX, point resolved_dex_path to the primary DEX entry
                    if let Some(first) = pkg.dex_entries.first() {
                        if let Some(p) = &first.path {
                            if p.is_file() {
                                resolved_dex_path = p.clone();
                            }
                        } else if let Ok(bytes) = pkg.read_entry(&first.name) {
                            let t_path = std::env::temp_dir().join(format!("rvs_dex_{}_{}.dex", std::process::id(), first.name.replace('/', "_")));
                            if std::fs::write(&t_path, &bytes).is_ok() {
                                resolved_dex_path = t_path.clone();
                                _temp_guard = TempFileGuard(Some(t_path));
                            }
                        }
                    }

                    apk::DexAnalysisResult {
                        file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                        classes_count: combined_classes.len(),
                        methods_count: total_methods,
                        strings_count: total_strings,
                        classes: combined_classes,
                        strings: Some(all_strings),
                        disassembly: None,
                        smali: None,
                        decompiled: None,
                    }
                }
            };

            // Apply class filter if specified
            if let Some(class_filter) = &class {
                analysis_result.classes.retain(|c| c.name.contains(class_filter));
                analysis_result.classes_count = analysis_result.classes.len();
                analysis_result.methods_count = analysis_result.classes.iter().map(|c| c.methods.len()).sum();
            }

            // Apply method filter if specified
            if let Some(method_filter) = &method {
                for c in &mut analysis_result.classes {
                    c.methods.retain(|m| m.name.contains(method_filter));
                }
                analysis_result.methods_count = analysis_result.classes.iter().map(|c| c.methods.len()).sum();
            }

            // Wire up --disasm and --smali flags: populate Dalvik bytecode disassembly
            if *disasm || *smali {
                let mut all_disasm = Vec::new();
                for c in &mut analysis_result.classes {
                    for m in &mut c.methods {
                        if let Some(code_offset) = m.code_offset {
                            let instruction_addr = code_offset + 16;
                            let insts_res = if let Some(insns) = m.insns_size {
                                apk::disassemble_dalvik_bounded(&resolved_dex_path, instruction_addr, insns)
                            } else {
                                apk::disassemble_dalvik_at(&resolved_dex_path, instruction_addr, 50)
                            };

                            if let Ok(insts) = insts_res {
                                m.disassembly = Some(insts.clone());
                                all_disasm.extend(insts);
                            }
                        }
                    }
                }
                if *disasm && !all_disasm.is_empty() {
                    analysis_result.disassembly = Some(all_disasm);
                }
            }

            // Wire up --smali flag: format matched classes and methods as Smali
            if *smali {
                let mut class_smalis = Vec::new();
                for c in &mut analysis_result.classes {
                    for m in &mut c.methods {
                        m.smali = Some(apk::format_method_smali(m));
                    }
                    let c_smali = apk::format_class_smali(c);
                    c.smali = Some(c_smali.clone());
                    class_smalis.push(c_smali);
                }
                if !class_smalis.is_empty() {
                    analysis_result.smali = Some(class_smalis.join("\n\n"));
                }
            }

            // Wire up --decompile flag: decompile matched methods using radare2 (af; pdc)
            if *decompile {
                let mut decompiled_methods = Vec::new();
                for c in &mut analysis_result.classes {
                    for m in &mut c.methods {
                        if let Some(code_offset) = m.code_offset {
                            let instruction_addr = code_offset + 16;
                            if let Ok(decomp) = apk::decompile_dalvik_method(&resolved_dex_path, instruction_addr) {
                                if !decomp.is_empty() {
                                    m.decompiled = Some(decomp.clone());
                                    decompiled_methods.push(decomp);
                                }
                            }
                        }
                    }
                }
                if !decompiled_methods.is_empty() {
                    analysis_result.decompiled = Some(decompiled_methods.join("\n\n"));
                }
            }

            if compact_flag {
                let comp = compact::CompactDexAnalysisResult::from(&analysis_result);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, analysis_result);
                resp.to_json(pretty).map_err(Into::into)
            }
        }

        ApkCommands::So {
            path,
            abi,
            library,
            symbol,
            xrefs,
        } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let file_bytes = if path.is_file() {
                Some(std::fs::read(path)?)
            } else {
                None
            };

            let is_archive_or_dir = path.is_dir() || file_bytes.as_ref().map(|b| {
                b.len() >= 4 && (&b[..4] == b"PK\x03\x04" || &b[..4] == b"PK\x05\x06")
            }).unwrap_or(false);

            let mut _temp_guard = TempFileGuard(None);
            let mut resolved_so_path = path.to_path_buf();

            let mut analysis = if !is_archive_or_dir {
                let bytes = file_bytes.unwrap();
                apk::parse_native_so_bytes(&bytes, &path.display().to_string())?
            } else {
                let pkg = ApkPackage::open(path)?;
                if pkg.native_libraries.is_empty() {
                    apk::NativeLibraryAnalysis {
                        file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                        architecture: "unknown".to_string(),
                        abi: "unknown".to_string(),
                        is_64_bit: false,
                        bits: 0,
                        elf_type: "NONE".to_string(),
                        endianness: "little".to_string(),
                        entry_point: 0,
                        soname: None,
                        needed_libraries: Vec::new(),
                        jni_functions: Vec::new(),
                        exported_symbols: Vec::new(),
                        imported_symbols: Vec::new(),
                        symbols: Vec::new(),
                        register_natives_detected: false,
                        xrefs: None,
                    }
                } else if library.is_some() || abi.is_some() {
                    let target_entry = if let Some(target_abi) = &abi {
                        let entries = pkg.native_libraries.get(target_abi).ok_or_else(|| {
                            AppError::FileNotFound(format!("ABI '{}' not found in package", target_abi))
                        })?;
                        if let Some(target_lib) = &library {
                            entries
                                .iter()
                                .find(|e| {
                                    e.name == *target_lib
                                        || e.name.ends_with(&format!("/{}", target_lib.trim_start_matches('/')))
                                        || e.name.ends_with(target_lib)
                                })
                                .ok_or_else(|| {
                                    AppError::FileNotFound(format!(
                                        "Library '{}' not found for ABI '{}'",
                                        target_lib, target_abi
                                    ))
                                })?
                        } else {
                            entries.first().ok_or_else(|| {
                                AppError::FileNotFound(format!("No native libraries found for ABI '{}'", target_abi))
                            })?
                        }
                    } else {
                        // abi is None, library is Some
                        let target_lib = library.as_ref().unwrap();
                        let mut found = None;
                        for entries in pkg.native_libraries.values() {
                            if let Some(entry) = entries.iter().find(|e| {
                                e.name == *target_lib
                                    || e.name.ends_with(&format!("/{}", target_lib.trim_start_matches('/')))
                                    || e.name.ends_with(target_lib)
                            }) {
                                found = Some(entry);
                                break;
                            }
                        }
                        found.ok_or_else(|| {
                            AppError::FileNotFound(format!("Library '{}' not found in package", target_lib))
                        })?
                    };

                    if let Some(p) = &target_entry.path {
                        if p.is_file() {
                            resolved_so_path = p.clone();
                        }
                    } else if let Ok(bytes) = pkg.read_entry(&target_entry.name) {
                        let t_path = std::env::temp_dir().join(format!(
                            "rvs_so_{}_{}.so",
                            std::process::id(),
                            target_entry.name.replace('/', "_")
                        ));
                        if std::fs::write(&t_path, &bytes).is_ok() {
                            resolved_so_path = t_path.clone();
                            _temp_guard = TempFileGuard(Some(t_path));
                        }
                    }

                    let bytes = pkg.read_entry(&target_entry.name)?;
                    apk::parse_native_so_bytes(&bytes, &target_entry.name)?
                } else {
                    // Resolve disk path for first available native library
                    if let Some((_, entries)) = pkg.native_libraries.iter().next() {
                        if let Some(first) = entries.first() {
                            if let Some(p) = &first.path {
                                if p.is_file() {
                                    resolved_so_path = p.clone();
                                }
                            } else if let Ok(bytes) = pkg.read_entry(&first.name) {
                                let t_path = std::env::temp_dir().join(format!(
                                    "rvs_so_{}_{}.so",
                                    std::process::id(),
                                    first.name.replace('/', "_")
                                ));
                                if std::fs::write(&t_path, &bytes).is_ok() {
                                    resolved_so_path = t_path.clone();
                                    _temp_guard = TempFileGuard(Some(t_path));
                                }
                            }
                        }
                    }

                    let mut analyses = pkg.analyze_native_libraries()?;
                    if analyses.is_empty() {
                        apk::NativeLibraryAnalysis {
                            file_name: path.file_name().unwrap_or_default().to_string_lossy().to_string(),
                            architecture: "unknown".to_string(),
                            abi: "unknown".to_string(),
                            is_64_bit: false,
                            bits: 0,
                            elf_type: "NONE".to_string(),
                            endianness: "little".to_string(),
                            entry_point: 0,
                            soname: None,
                            needed_libraries: Vec::new(),
                            jni_functions: Vec::new(),
                            exported_symbols: Vec::new(),
                            imported_symbols: Vec::new(),
                            symbols: Vec::new(),
                            register_natives_detected: false,
                            xrefs: None,
                        }
                    } else if analyses.len() == 1 {
                        analyses.remove(0)
                    } else {
                        let mut combined = analyses.remove(0);
                        for other in analyses {
                            combined.jni_functions.extend(other.jni_functions);
                            combined.exported_symbols.extend(other.exported_symbols);
                            combined.imported_symbols.extend(other.imported_symbols);
                            combined.needed_libraries.extend(other.needed_libraries);
                            combined.symbols.extend(other.symbols);
                            combined.register_natives_detected |= other.register_natives_detected;
                        }
                        combined.jni_functions.sort_by(|a, b| a.name.cmp(&b.name));
                        combined.jni_functions.dedup_by(|a, b| a.name == b.name);
                        combined.exported_symbols.sort();
                        combined.exported_symbols.dedup();
                        combined.imported_symbols.sort();
                        combined.imported_symbols.dedup();
                        combined.needed_libraries.sort();
                        combined.needed_libraries.dedup();
                        combined.symbols.sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
                        combined.symbols.dedup_by(|a, b| a.name == b.name && a.is_import == b.is_import);
                        combined
                    }
                }
            };

            // Apply symbol filter if specified
            if let Some(sym_filter) = &symbol {
                analysis.jni_functions.retain(|j| j.name.contains(sym_filter));
                analysis.exported_symbols.retain(|s| s.contains(sym_filter));
                analysis.imported_symbols.retain(|s| s.contains(sym_filter));
                analysis.symbols.retain(|s| s.name.contains(sym_filter) || s.demangled_name.as_ref().map(|d| d.contains(sym_filter)).unwrap_or(false));
            }

            // Wire up --xrefs flag: extract cross references for JNI functions
            if *xrefs && resolved_so_path.exists() {
                let mut xrefs_map = std::collections::HashMap::new();
                for jni in &mut analysis.jni_functions {
                    if let Ok(resp) = apk::analyze_jni_xrefs(&resolved_so_path, &jni.name) {
                        jni.xrefs = Some(resp.clone());
                        xrefs_map.insert(jni.name.clone(), resp);
                    }
                }
                if let Some(sym_filter) = &symbol {
                    if !xrefs_map.contains_key(sym_filter) {
                        if let Ok(resp) = apk::analyze_jni_xrefs(&resolved_so_path, sym_filter) {
                            xrefs_map.insert(sym_filter.clone(), resp);
                        }
                    }
                }
                if !xrefs_map.is_empty() {
                    analysis.xrefs = Some(xrefs_map);
                }
            }

            if compact_flag {
                let comp = compact::CompactNativeLibraryAnalysis::from(&analysis);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, analysis);
                resp.to_json(pretty).map_err(Into::into)
            }
        }

        ApkCommands::Resources {
            path,
            list,
            extract,
            dump,
        } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let pkg = ApkPackage::open(path)?;
            let resources_data = apk::analyze_apk_resources(
                &pkg,
                *list,
                extract.as_deref(),
                dump.as_deref(),
            )?;

            if compact_flag {
                let comp = compact::CompactApkResourcesData::from(&resources_data);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, resources_data);
                resp.to_json(pretty).map_err(Into::into)
            }
        }

        ApkCommands::Signature { path, verify } => {
            if !path.exists() {
                return Err(AppError::FileNotFound(path.display().to_string()));
            }
            if path.is_file() {
                let meta = std::fs::metadata(path)?;
                if meta.len() == 0 {
                    return Err(AppError::ZeroByteFile(path.display().to_string()));
                }
            }

            let sig_info = apk::verify_apk_signature(path, *verify)?;

            if compact_flag {
                let comp = compact::CompactApkSignatureData::from(&sig_info);
                let resp = make_compact_response(command_name, target_str, comp);
                resp.to_json(pretty).map_err(Into::into)
            } else {
                let resp = ApiResponse::success(command_name, target_str, sig_info);
                resp.to_json(pretty).map_err(Into::into)
            }
        }
    }
}
