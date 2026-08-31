use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use crate::analysis::xrefs::{XrefDirection, XrefKindFilter};

#[derive(Parser, Debug)]
#[command(
    name = "rvs",
    author = "Teamwork Binary Intelligence",
    version,
    about = "Radare2-backed binary analysis and patching tool for AI agents and reverse engineers",
    long_about = "A high-performance CLI tool wrapping radare2 to provide structured JSON outputs for binary analysis, control-flow extraction, prologue/epilogue detection, and deterministic binary patching."
)]
pub struct Cli {
    /// Target binary file to inspect or patch
    #[arg(short = 'f', long = "file", global = true)]
    pub file: Option<PathBuf>,

    /// Output format engine (json, agent/compact, jsonl, markdown)
    #[arg(long = "format", global = true, value_enum, default_value = "json")]
    pub format: OutputFormat,

    /// Emit minimal JSON optimized for AI agents / machine consumers.
    /// Removes redundant fields (decimal addresses, duplicate opcode,
    /// raw bytes, family/type metadata) to reduce output size ~60-75%.
    #[arg(short = 'c', long = "compact", global = true)]
    pub compact: bool,

    /// Override target architecture (e.g. x86, arm, mips)
    #[arg(short = 'a', long = "arch", global = true)]
    pub arch: Option<String>,

    /// Override architecture bitness (16, 32, 64)
    #[arg(short = 'b', long = "bits", global = true)]
    pub bits: Option<u32>,

    /// Format output as pretty-printed JSON (defaults to compact single-line JSON)
    #[arg(long = "pretty", global = true)]
    pub pretty: bool,

    /// Suppress diagnostic logs on stderr
    #[arg(short = 'q', long = "quiet", global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Json,
    #[value(alias = "compact")]
    Agent,
    Jsonl,
    Markdown,
    // Formats supported for graph rendering
    Ascii,
    Tree,
    Dot,
    Mermaid,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Retrieve binary metadata, format, architecture, and security properties
    #[command(alias = "i")]
    Info,

    /// Analyze binary structures, functions, blocks, and graphs
    #[command(subcommand, alias = "a")]
    Analyze(AnalyzeCommands),

    /// Apply binary modifications and patches
    #[command(subcommand, alias = "p")]
    Patch(PatchCommands),

    /// High-level composite commands designed for AI agents
    #[command(subcommand, alias = "ag")]
    Agent(AgentCommands),

    /// List strings found in the binary
    #[command(alias = "str")]
    Strings {
        /// Minimum string length
        #[arg(short = 'n', long = "min-len", default_value = "4")]
        min_len: usize,
    },

    /// List binary symbols, virtual/physical addresses, types, bindings
    #[command(alias = "sym")]
    Symbols {
        /// Filter symbols by name substring
        #[arg(short = 'F', long = "filter")]
        filter: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentCommands {
    /// Autonomous binary triage & reconnaissance
    Triage,

    /// Extract pseudo-C decompilation, metrics, and references for a function
    Decompile {
        /// Target function name or address (e.g. 'main', 'check_auth_token', '0x1146')
        #[arg(required = true)]
        function: String,
    },

    /// Control-flow branch gate & decision node extraction for a function
    Flow {
        /// Target function name or address
        #[arg(required = true)]
        function: String,
    },

    /// Comprehensive cross-references analysis (callers, callees, data references)
    Xrefs {
        /// Target function, symbol, string, or address
        #[arg(required = true)]
        target: String,
    },

    /// Dry-run simulation and atomic multi-step binary patching plan execution
    #[command(name = "patch-plan")]
    PatchPlan {
        /// JSON patch plan string or path to JSON plan file
        #[arg(long = "plan", required = true)]
        plan: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AnalyzeCommands {
    /// List all analyzed functions with addresses, sizes, and properties
    #[command(alias = "funcs", alias = "fn")]
    Functions {
        /// Filter functions by name regex or substring
        #[arg(short = 'F', long = "filter")]
        filter: Option<String>,

        /// Include full function details (arguments, local variable counts)
        #[arg(short = 'd', long = "detail")]
        detail: bool,
    },

    /// Extract basic blocks for a specific function
    #[command(alias = "bb")]
    Blocks {
        /// Target function name (e.g. 'main', 'sym.check_auth') or address (e.g. '0x1146')
        #[arg(required = true)]
        target: String,

        /// Include disassembled instructions inside each block
        #[arg(long = "disasm", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        disasm: bool,
    },

    /// Generate call graph or control-flow graph (CFG)
    #[command(alias = "cg")]
    Graph {
        /// Target function name or address (optional: global callgraph if omitted)
        target: Option<String>,

        /// Graph type: Call Graph or Control Flow Graph
        #[arg(short = 't', long = "type", default_value = "callgraph")]
        graph_type: GraphType,
    },

    /// Identify function prologues and epilogues
    #[command(alias = "pe", alias = "frame")]
    PrologueEpilogue {
        /// Target function (analyzes all functions if omitted)
        target: Option<String>,
    },

    /// Extract cross-references (xrefs) to and from a symbol, function, string, or address
    #[command(alias = "xref", alias = "x")]
    Xrefs {
        /// Target function name, symbol, string flag, or virtual address (e.g. 'main', '0x2004', 'sym.imp.puts')
        #[arg(required = true)]
        target: String,

        /// Direction of references: 'all' (default, bidirectional), 'to' (incoming callers/references), or 'from' (outgoing)
        #[arg(short = 't', long = "type", default_value = "all")]
        xref_type: XrefDirection,

        /// Optional filter by reference kind (call, code, data, string, read, write)
        #[arg(short = 'k', long = "kind")]
        kind: Option<XrefKindFilter>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum PatchCommands {
    /// Patch an assembly instruction at a specific address or symbol offset
    #[command(alias = "ins")]
    Instruction {
        /// Target memory address (hex or decimal) or symbol+offset (e.g., '0x1146' or 'sym.check_auth+12')
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Assembly instruction to write (e.g., 'mov eax, 1' or 'nop')
        #[arg(short = 'i', long = "assembly", required_unless_present = "nop_bytes")]
        assembly: Option<String>,

        /// Replace target instruction(s) with NOP sled of specified byte count
        #[arg(long = "nop", conflicts_with = "assembly")]
        nop_bytes: Option<usize>,

        /// Create a backup file (.bak) before writing
        #[arg(long = "backup", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        backup: bool,
    },

    /// Patch or overwrite a string literal in data/rodata
    #[command(alias = "str")]
    String {
        /// Target memory address of the string
        #[arg(short = 'A', long = "addr", required_unless_present = "old_string")]
        addr: Option<String>,

        /// Old string to search for and replace
        #[arg(long = "old", required_unless_present = "addr")]
        old_string: Option<String>,

        /// New replacement string
        #[arg(short = 'n', long = "new", required = true)]
        new_string: String,

        /// Zero-pad remaining bytes if new string is shorter than old string
        #[arg(long = "pad-null", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        pad_null: bool,

        /// Prevent writes that exceed the original string length
        #[arg(long = "strict-length", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        strict_length: bool,

        /// Create a backup file (.bak) before writing
        #[arg(long = "backup", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        backup: bool,
    },

    /// Patch raw bytes (hex string) at a specific address
    #[command(alias = "hex", alias = "raw")]
    Bytes {
        /// Target memory address (hex or decimal)
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Hexadecimal byte sequence (e.g., '9090' or 'b801000000')
        #[arg(short = 'x', long = "hex", required = true)]
        hex_bytes: String,

        /// Create a backup file (.bak) before writing
        #[arg(long = "backup", default_value = "true", num_args = 0..=1, default_missing_value = "true")]
        backup: bool,
    },
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphType {
    Callgraph,
    Cfg,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphFormat {
    Json,
    Ascii,
    Tree,
    Dot,
    Mermaid,
}

impl From<OutputFormat> for GraphFormat {
    fn from(fmt: OutputFormat) -> Self {
        match fmt {
            OutputFormat::Json | OutputFormat::Agent | OutputFormat::Jsonl | OutputFormat::Markdown => {
                GraphFormat::Json
            }
            OutputFormat::Ascii => GraphFormat::Ascii,
            OutputFormat::Tree => GraphFormat::Tree,
            OutputFormat::Dot => GraphFormat::Dot,
            OutputFormat::Mermaid => GraphFormat::Mermaid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_clap_command_schema_validity() {
        // Assert that the entire clap CLI command tree is self-consistent
        // and contains no illegal global/required conflicts.
        Cli::command().debug_assert();
    }

    #[test]
    fn test_global_flags_parsed_before_and_after_subcommand() {
        // Test -f before subcommand
        let cli1 = Cli::try_parse_from(["rvs", "-f", "/bin/ls", "info"]).unwrap();
        assert_eq!(cli1.file, Some(PathBuf::from("/bin/ls")));
        assert!(matches!(cli1.command, Commands::Info));

        // Test -f after subcommand
        let cli2 = Cli::try_parse_from(["rvs", "info", "-f", "/bin/ls"]).unwrap();
        assert_eq!(cli2.file, Some(PathBuf::from("/bin/ls")));
        assert!(matches!(cli2.command, Commands::Info));

        // Test global flags --arch, --bits, --pretty, --quiet, --format
        let cli3 = Cli::try_parse_from([
            "rvs",
            "-f", "/bin/ls",
            "--arch", "x86",
            "--bits", "64",
            "--pretty",
            "--format", "jsonl",
            "-q",
            "analyze", "functions",
            "--filter", "main",
            "--detail",
        ]).unwrap();
        assert_eq!(cli3.arch.as_deref(), Some("x86"));
        assert_eq!(cli3.bits, Some(64));
        assert!(cli3.pretty);
        assert!(cli3.quiet);
        assert_eq!(cli3.format, OutputFormat::Jsonl);
    }

    #[test]
    fn test_patch_instruction_argument_constraints() {
        // 1. Valid with assembly
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "instruction",
            "--addr", "0x1000", "--assembly", "mov eax, 1",
        ]).unwrap();
        if let Commands::Patch(PatchCommands::Instruction { addr, assembly, nop_bytes, backup }) = cli.command {
            assert_eq!(addr, "0x1000");
            assert_eq!(assembly.as_deref(), Some("mov eax, 1"));
            assert_eq!(nop_bytes, None);
            assert!(backup);
        } else {
            panic!("Expected PatchCommands::Instruction");
        }

        // 2. Valid with nop
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "instruction",
            "--addr", "0x1000", "--nop", "4",
        ]).unwrap();
        if let Commands::Patch(PatchCommands::Instruction { nop_bytes, .. }) = cli.command {
            assert_eq!(nop_bytes, Some(4));
        }

        // 3. Invalid: both assembly and nop
        let res = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "instruction",
            "--addr", "0x1000", "--assembly", "nop", "--nop", "4",
        ]);
        assert!(res.is_err());
    }

    #[test]
    fn test_patch_string_argument_constraints() {
        // 1. Valid with --old
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "string",
            "--old", "FOO", "--new", "BAR",
        ]).unwrap();
        assert!(matches!(cli.command, Commands::Patch(PatchCommands::String { .. })));

        // 2. Valid with --addr
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "string",
            "--addr", "0x2000", "--new", "BAR",
        ]).unwrap();
        assert!(matches!(cli.command, Commands::Patch(PatchCommands::String { .. })));

        // 3. Invalid: missing both --addr and --old
        let res = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "string",
            "--new", "BAR",
        ]);
        assert!(res.is_err());
    }

    #[test]
    fn test_patch_bytes_argument_constraints() {
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "bytes",
            "--addr", "0x1000", "--hex", "9090",
        ]).unwrap();
        if let Commands::Patch(PatchCommands::Bytes { addr, hex_bytes, backup }) = cli.command {
            assert_eq!(addr, "0x1000");
            assert_eq!(hex_bytes, "9090");
            assert!(backup);
        }

        // Missing --hex
        let res = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "patch", "bytes",
            "--addr", "0x1000",
        ]);
        assert!(res.is_err());
    }

    #[test]
    fn test_analyze_xrefs_cli_parsing() {
        let cli = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "analyze", "xrefs", "main",
            "--type", "to", "--kind", "call",
        ]).unwrap();

        if let Commands::Analyze(AnalyzeCommands::Xrefs { target, xref_type, kind }) = cli.command {
            assert_eq!(target, "main");
            assert_eq!(xref_type, XrefDirection::To);
            assert_eq!(kind, Some(XrefKindFilter::Call));
        } else {
            panic!("Expected AnalyzeCommands::Xrefs");
        }
    }

    #[test]
    fn test_agent_commands_parsing() {
        let cli1 = Cli::try_parse_from(["rvs", "-f", "test.bin", "agent", "triage"]).unwrap();
        assert!(matches!(cli1.command, Commands::Agent(AgentCommands::Triage)));

        let cli2 = Cli::try_parse_from(["rvs", "-f", "test.bin", "agent", "decompile", "main"]).unwrap();
        if let Commands::Agent(AgentCommands::Decompile { function }) = cli2.command {
            assert_eq!(function, "main");
        } else {
            panic!("Expected AgentCommands::Decompile");
        }

        let cli3 = Cli::try_parse_from(["rvs", "-f", "test.bin", "agent", "flow", "main"]).unwrap();
        if let Commands::Agent(AgentCommands::Flow { function }) = cli3.command {
            assert_eq!(function, "main");
        } else {
            panic!("Expected AgentCommands::Flow");
        }

        let cli4 = Cli::try_parse_from(["rvs", "-f", "test.bin", "agent", "xrefs", "main"]).unwrap();
        if let Commands::Agent(AgentCommands::Xrefs { target }) = cli4.command {
            assert_eq!(target, "main");
        } else {
            panic!("Expected AgentCommands::Xrefs");
        }

        let cli5 = Cli::try_parse_from([
            "rvs", "-f", "test.bin", "agent", "patch-plan", "--plan", "{\"name\":\"test\"}",
        ]).unwrap();
        if let Commands::Agent(AgentCommands::PatchPlan { plan }) = cli5.command {
            assert_eq!(plan, "{\"name\":\"test\"}");
        } else {
            panic!("Expected AgentCommands::PatchPlan");
        }
    }
}
