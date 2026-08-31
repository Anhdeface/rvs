pub mod info;
pub mod functions;
pub mod blocks;
pub mod frame;
pub mod graph;
pub mod strings;
pub mod symbols;
pub mod xrefs;

pub use info::{get_binary_info, BinaryInfo, SecurityMitigations};
pub use functions::{analyze_functions, FunctionsResponse, FunctionInfo};
pub use blocks::{analyze_blocks, BasicBlocksResponse, BasicBlockInfo, InstructionInfo};
pub use frame::{analyze_prologue_epilogue, PrologueEpilogueResponse, FunctionFrameInfo, FrameBoundary, FrameInstruction};
pub use graph::{analyze_graph, GraphResponse, GraphNode, GraphEdge};
pub use strings::{list_strings, StringsResponse, StringEntry};
pub use symbols::{list_symbols, SymbolsResponse, SymbolEntry};
pub use xrefs::{analyze_xrefs, XrefsResponse, XrefEntry, XrefDirection, XrefKindFilter};

