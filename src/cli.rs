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
    #[arg(long = "format", value_enum, default_value = "json")]
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

    /// Execution timeout in seconds for radare2 subprocesses
    #[arg(long = "timeout", global = true)]
    pub timeout: Option<u64>,

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

    /// Dynamic reverse engineering and ESIL emulation
    #[command(subcommand, alias = "dyn", alias = "emu")]
    Dynamic(DynamicCommands),

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

    /// Dynamic runtime instrumentation and live process hooking via r2frida
    #[command(subcommand, alias = "f", alias = "fr")]
    Frida(FridaCommands),
}

#[derive(Subcommand, Debug, Clone)]
pub enum FridaCommands {
    /// Check r2frida environment and installation status
    #[command(name = "env-check")]
    EnvCheck,

    /// Attach to a running process by PID, process name, or full Frida URI
    Attach {
        /// Target PID (e.g. 1234), process name (e.g. 'firefox'), or frida URI
        #[arg(required = true, allow_hyphen_values = true)]
        target: String,

        /// Device type: local, usb, or remote IP:port
        #[arg(short = 'D', long = "device", default_value = "local")]
        device: String,

        /// Timeout in seconds for attach operation
        #[arg(long = "timeout")]
        timeout: Option<u64>,
    },

    /// Spawn a new target executable under Frida dynamic instrumentation
    Spawn {
        /// Path to target executable
        #[arg(required = true)]
        path: PathBuf,

        /// Command line arguments for target process
        #[arg(long = "args", num_args = 1.., allow_hyphen_values = true)]
        args: Vec<String>,


        /// Device type: local, usb, or remote IP:port
        #[arg(short = 'D', long = "device", default_value = "local")]
        device: String,

        /// Timeout in seconds for spawn operation
        #[arg(long = "timeout")]
        timeout: Option<u64>,
    },

    /// List loaded modules and shared libraries in target process memory space (:il)
    Modules {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Filter module names by substring
        #[arg(short = 'F', long = "filter")]
        filter: Option<String>,

        /// Maximum number of modules to return (pagination, default: 30)
        #[arg(short = 'l', long = "limit", allow_hyphen_values = true)]
        limit: Option<i64>,

        /// Starting index offset for module pagination
        #[arg(short = 'o', long = "offset", allow_hyphen_values = true)]
        offset: Option<i64>,
    },

    /// Enumerate symbols, exports, and functions in target process or specific module (:is)
    Symbols {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Specific module to inspect (e.g. 'libc.so.6' or main binary)
        #[arg(short = 'm', long = "module")]
        module: Option<String>,

        /// Filter symbol names by substring or regex
        #[arg(short = 'F', long = "filter")]
        filter: Option<String>,

        /// Maximum number of symbols to return (pagination)
        #[arg(short = 'l', long = "limit", allow_hyphen_values = true)]
        limit: Option<i64>,

        /// Starting index offset for symbol pagination
        #[arg(short = 'o', long = "offset", allow_hyphen_values = true)]
        offset: Option<i64>,
    },

    /// Enumerate Objective-C, Swift, or Java classes in target process (:ic)
    Classes {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Filter class names by substring
        #[arg(short = 'F', long = "filter")]
        filter: Option<String>,

        /// Maximum number of classes to return (pagination, default: 50)
        #[arg(short = 'l', long = "limit", allow_hyphen_values = true)]
        limit: Option<i64>,

        /// Starting index offset for class pagination
        #[arg(short = 'o', long = "offset", allow_hyphen_values = true)]
        offset: Option<i64>,
    },

    /// Register dynamic function hook to trace arguments or inspect execution (:dtf)
    Hook {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Target function address or symbol name
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Argument format specifier (e.g. 'i', 'x', 'z', 'h', '^', '+')
        #[arg(long = "format", alias = "fmt")]
        format: Option<String>,
    },

    /// Trace CPU register values at function execution (:dtr)
    #[command(name = "trace-regs")]
    TraceRegs {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Target function address or symbol name
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Comma-separated list of register names to trace (e.g. 'rax,rdi')
        #[arg(short = 'r', long = "regs", required = true)]
        regs: String,
    },

    /// Install return value replacement hook on target function
    #[command(name = "hook-return")]
    HookReturn {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Target function address or symbol name
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Replacement return value in hex or decimal (e.g. '0x1')
        #[arg(long = "retval", required = true)]
        retval: String,
    },

    /// List all currently active hooks in the target process (:dtj)
    #[command(name = "hooks-list")]
    HooksList {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,
    },

    /// Remove a registered dynamic hook by ID (:dt-)
    #[command(name = "hook-remove")]
    HookRemove {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Hook identifier to remove
        #[arg(long = "id", required = true)]
        id: String,
    },

    /// Inject and evaluate custom JavaScript snippet or script file (:eval / :.)
    Script {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// JavaScript code snippet to evaluate inline via :eval
        #[arg(long = "code", conflicts_with = "file")]
        code: Option<String>,

        /// Path to external JavaScript file to load via :.
        #[arg(long = "file")]
        file: Option<PathBuf>,

        /// Execution timeout in seconds
        #[arg(long = "timeout")]
        timeout: Option<u64>,
    },

    /// Invoke an exported Frida RPC method (rpc.exports.<method>)
    Rpc {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Exported RPC method name
        #[arg(short = 'm', long = "method", required = true)]
        method: String,

        /// Arguments passed to the RPC method (JSON array string or comma-separated)
        #[arg(long = "args")]
        args: Option<String>,

        /// Execution timeout in seconds
        #[arg(long = "timeout")]
        timeout: Option<u64>,
    },

    /// Read raw memory bytes from live target process space (:x)
    #[command(name = "mem-read")]
    MemRead {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Virtual memory address (hex string or symbol)
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Number of bytes to read
        #[arg(short = 'l', long = "len", alias = "length", default_value = "32")]
        len: usize,
    },

    /// Write and patch memory bytes directly in live process space (:w)
    #[command(name = "mem-write")]
    MemWrite {
        /// Target PID, process name, or URI
        #[arg(short = 't', long = "target", required = true)]
        target: String,

        /// Virtual memory address (hex string or symbol)
        #[arg(short = 'A', long = "addr", required = true)]
        addr: String,

        /// Hexadecimal byte string to write (e.g. '9090' or '31c0c3')
        #[arg(short = 'd', long = "data", alias = "hex", alias = "bytes", required = true)]
        data: String,

        /// Ensure memory page is writable (RWX) before writing
        #[arg(long = "protect", default_value = "true", action = clap::ArgAction::Set)]
        protect: bool,
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

    /// Dynamic emulation with AI summary, register diffs, and decision gate branch outcomes
    #[command(alias = "emu")]
    Emulate {
        /// Target function name or address
        #[arg(required = true)]
        target: String,

        /// Maximum steps to emulate
        #[arg(short = 's', long = "steps", default_value = "100")]
        steps: usize,

        /// Stop emulation at address
        #[arg(short = 'u', long = "until")]
        until: Option<String>,

        /// Preset registers before execution (format: 'reg=val', e.g. 'rax=0x42', can be repeated)
        #[arg(short = 'r', long = "reg")]
        reg: Vec<String>,

        /// Memory address to inspect after emulation
        #[arg(long = "read-mem")]
        read_mem: Option<String>,

        /// Length of memory to inspect (default: 32)
        #[arg(long = "mem-len", default_value = "32")]
        mem_len: usize,
    },

    /// Execution trace recording instruction sequence and register deltas
    #[command(alias = "tr")]
    Trace {
        /// Target function name or address
        #[arg(required = true)]
        target: String,

        /// Number of steps to trace
        #[arg(short = 's', long = "steps", default_value = "20")]
        steps: usize,

        /// Preset registers before trace (format: 'reg=val', can be repeated)
        #[arg(short = 'r', long = "reg")]
        reg: Vec<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum DynamicCommands {
    /// Emulate execution of a function or address range using radare2 ESIL
    #[command(alias = "emu")]
    Emulate {
        /// Target function name or start address (e.g. 'main', 'sym.check_auth', '0x1146')
        #[arg(required = true)]
        target: String,

        /// Maximum number of ESIL steps to emulate (default: 100)
        #[arg(short = 's', long = "steps", default_value = "100")]
        steps: usize,

        /// Stop emulation when program counter reaches this address
        #[arg(short = 'u', long = "until")]
        until: Option<String>,

        /// Preset registers before execution (format: 'reg=val', e.g. 'rax=1', can be repeated)
        #[arg(short = 'r', long = "reg")]
        reg_set: Vec<String>,

        /// Read memory at address after emulation (hex or symbol)
        #[arg(long = "read-mem")]
        read_mem: Option<String>,

        /// Number of memory bytes to read (default: 32)
        #[arg(long = "mem-len", default_value = "32")]
        mem_len: usize,
    },

    /// Trace instruction execution step-by-step with register diffs
    #[command(alias = "tr")]
    Trace {
        /// Target function name or start address
        #[arg(required = true)]
        target: String,

        /// Number of instructions to trace (default: 20)
        #[arg(short = 's', long = "steps", default_value = "20")]
        steps: usize,

        /// Preset registers before trace (format: 'reg=val', e.g. 'rax=1', can be repeated)
        #[arg(short = 'r', long = "reg")]
        reg_set: Vec<String>,
    },

    /// Emulate single step (or N steps) and show register changes
    Step {
        /// Target function name or start address
        #[arg(required = true)]
        target: String,

        /// Number of steps (default: 1)
        #[arg(short = 'n', long = "count", alias = "steps", short_alias = 's', default_value = "1")]
        count: usize,

        /// Preset registers before step (format: 'reg=val', can be repeated)
        #[arg(short = 'r', long = "reg")]
        reg_set: Vec<String>,
    },

    /// Native dynamic debugging subcommands using Linux ptrace
    #[command(subcommand, alias = "dbg")]
    Debug(DebugCommands),
}

#[derive(Subcommand, Debug, Clone)]
pub enum DebugCommands {
    /// Spawn target executable under native ptrace debugger
    Spawn {
        /// Target binary file (if not provided, uses global -f/--file)
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,

        /// Arguments passed to the debugged process
        #[arg(long = "args", allow_hyphen_values = true)]
        args: Vec<String>,

        /// String or file to feed into target stdin
        #[arg(long = "stdin")]
        stdin: Option<String>,

        /// Disable ASLR for reproducible memory addresses
        #[arg(long = "no-aslr", default_value = "true")]
        no_aslr: bool,

        /// Validate breakpoint addresses fall within mapped memory
        #[arg(long = "bpinmaps", default_value = "true")]
        bpinmaps: bool,
    },

    /// Attach to an existing running process by PID
    Attach {
        /// Process ID to attach
        #[arg(required = true, value_name = "PID")]
        pid: u32,
    },

    /// Continue execution until breakpoint, signal, or process exit
    Continue {
        /// Debug session ID
        #[arg(value_name = "SESSION_ID")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,

        /// Continue execution until specified address or symbol
        #[arg(short = 'u', long = "until")]
        until: Option<String>,
    },

    /// Single step or step over instructions
    Step {
        /// Debug session ID
        #[arg(value_name = "SESSION_ID")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,

        /// Step type: instruction (default), over, out, line
        #[arg(short = 't', long = "type", default_value = "instruction")]
        step_type: String,

        /// Number of steps to execute
        #[arg(short = 'n', long = "count", default_value = "1")]
        count: usize,
    },

    /// Manage software and hardware breakpoints
    #[command(alias = "bp")]
    Breakpoint {
        /// Debug session ID (or action if positional)
        #[arg(value_name = "SESSION_OR_ACTION")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,

        /// Breakpoint action: add, remove, list, clear
        #[arg(long = "action", default_value = "list")]
        action: String,

        /// Target address or symbol (flag option)
        #[arg(long = "addr")]
        addr: Option<String>,

        /// Target address or symbol (positional)
        #[arg(value_name = "ADDR")]
        pos_addr: Option<String>,

        /// Hardware breakpoint (DR0-DR3)
        #[arg(long = "hw")]
        hw: bool,
    },

    /// Inspect or modify CPU registers
    #[command(alias = "regs")]
    Registers {
        /// Debug session ID
        #[arg(value_name = "SESSION_ID")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,

        /// Modify registers (format: 'reg=val', e.g. 'rax=0x1337', can be repeated)
        #[arg(short = 'r', long = "set", alias = "reg")]
        reg_set: Vec<String>,

        /// Calculate and return register differences since previous halt
        #[arg(long = "diff")]
        diff: bool,
    },

    /// Inspect virtual memory maps, read or write live memory
    #[command(alias = "mem")]
    Memory {
        /// Debug session ID
        #[arg(value_name = "SESSION_OR_ACTION")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,

        /// Memory action: maps, read, write
        #[arg(long = "action", default_value = "read")]
        action: String,

        /// Address or symbol in target memory (flag option)
        #[arg(long = "addr")]
        addr: Option<String>,

        /// Address or symbol in target memory (positional)
        #[arg(value_name = "ADDR")]
        pos_addr: Option<String>,

        /// Length in bytes to read
        #[arg(short = 'l', long = "len", alias = "length", default_value = "32")]
        len: Option<usize>,

        /// Hexadecimal bytes to write (e.g. '90909090')
        #[arg(short = 'd', long = "data", alias = "hex", alias = "bytes")]
        data: Option<String>,
    },

    /// Terminate debug session and kill or detach process
    #[command(alias = "close")]
    Kill {
        /// Debug session ID
        #[arg(value_name = "SESSION_ID")]
        session_id: Option<String>,

        /// Debug session ID (flag option)
        #[arg(short = 's', long = "session")]
        session: Option<String>,
    },

    /// List all active debug sessions
    #[command(alias = "sessions", alias = "ls")]
    ListSessions,

    /// Query or control the persistent debug session daemon
    Daemon {
        /// Query daemon status and active sessions
        #[arg(long = "status")]
        status: bool,

        /// Stop and terminate the running daemon
        #[arg(long = "stop")]
        stop: bool,

        /// Start daemon in foreground (used internally by auto-spawner)
        #[arg(long = "start")]
        start: bool,
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

        /// Output format engine (json, agent/compact, jsonl, markdown)
        #[arg(long = "format")]
        format: Option<OutputFormat>,
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

        /// Output format (json, ascii, tree, dot, mermaid)
        #[arg(long = "format")]
        format: Option<OutputFormat>,
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

        /// Output format (json, jsonl, markdown)
        #[arg(long = "format")]
        format: Option<OutputFormat>,
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

        if let Commands::Analyze(AnalyzeCommands::Xrefs { target, xref_type, kind, .. }) = cli.command {
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

    #[test]
    fn test_frida_cli_subcommands_parsed() {
        // env-check
        let cli1 = Cli::try_parse_from(["rvs", "frida", "env-check"]).unwrap();
        assert!(matches!(cli1.command, Commands::Frida(FridaCommands::EnvCheck)));

        // attach positive PID
        let cli2 = Cli::try_parse_from(["rvs", "frida", "attach", "12345"]).unwrap();
        if let Commands::Frida(FridaCommands::Attach { target, .. }) = cli2.command {
            assert_eq!(target, "12345");
        } else {
            panic!("Expected FridaCommands::Attach");
        }

        // attach negative PID captured via allow_hyphen_values
        let cli3 = Cli::try_parse_from(["rvs", "frida", "attach", "-1"]).unwrap();
        if let Commands::Frida(FridaCommands::Attach { target, .. }) = cli3.command {
            assert_eq!(target, "-1");
        } else {
            panic!("Expected FridaCommands::Attach with -1");
        }

        // spawn with args
        let cli4 = Cli::try_parse_from(["rvs", "frida", "spawn", "/bin/ls", "--args", "-l", "-a"]).unwrap();
        if let Commands::Frida(FridaCommands::Spawn { path, args, .. }) = cli4.command {
            assert_eq!(path, PathBuf::from("/bin/ls"));
            assert_eq!(args, vec!["-l", "-a"]);
        } else {
            panic!("Expected FridaCommands::Spawn");
        }

        // symbols with negative pagination
        let cli5 = Cli::try_parse_from([
            "rvs", "frida", "symbols", "--target", "0", "--limit", "-10", "--offset", "-5",
        ]).unwrap();
        if let Commands::Frida(FridaCommands::Symbols { target, limit, offset, .. }) = cli5.command {
            assert_eq!(target, "0");
            assert_eq!(limit, Some(-10));
            assert_eq!(offset, Some(-5));
        } else {
            panic!("Expected FridaCommands::Symbols");
        }

        // hook with format
        let cli6 = Cli::try_parse_from([
            "rvs", "frida", "hook", "--target", "0", "--addr", "0x401000", "--format", "x",
        ]).unwrap();
        if let Commands::Frida(FridaCommands::Hook { target, addr, format }) = cli6.command {
            assert_eq!(target, "0");
            assert_eq!(addr, "0x401000");
            assert_eq!(format.as_deref(), Some("x"));
        } else {
            panic!("Expected FridaCommands::Hook");
        }
    }
}
