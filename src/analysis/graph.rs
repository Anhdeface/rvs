use std::collections::{BTreeMap, BTreeSet, HashSet};
use serde::{Deserialize, Serialize};
use crate::cli::{GraphFormat, GraphType};
use crate::r2::R2Driver;
use crate::response::AppError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GraphResponse {
    pub graph_type: String,
    pub target: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendered: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adjacency: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub edge_type: String,
}

pub fn analyze_graph(
    driver: &R2Driver,
    target: Option<&str>,
    graph_type: GraphType,
    format: GraphFormat,
) -> Result<GraphResponse, AppError> {
    match graph_type {
        GraphType::Callgraph => generate_callgraph(driver, target, format),
        GraphType::Cfg => generate_cfg(driver, target, format),
    }
}

fn generate_callgraph(
    driver: &R2Driver,
    target: Option<&str>,
    format: GraphFormat,
) -> Result<GraphResponse, AppError> {
    let (raw_funcs, raw_cg): (Vec<serde_json::Value>, Vec<serde_json::Value>) = if let Some(t) = target {
        let batch = driver.cmd_batch(&[
            "aa; aflj",
            &format!("s {}; agcj", t),
        ])?;
        (
            R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or("")).unwrap_or_default(),
            batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default(),
        )
    } else {
        let batch = driver.cmd_batch(&[
            "aa; aflj",
            "agCj",
        ])?;
        (
            R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or("")).unwrap_or_default(),
            batch.get(1).and_then(|s| R2Driver::parse_json(s).ok()).unwrap_or_default(),
        )
    };

    let mut func_map: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for f in &raw_funcs {
        let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let addr = f.get("offset").or_else(|| f.get("addr")).and_then(|v| v.as_u64()).unwrap_or(0);
        let size = f.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        if !name.is_empty() {
            func_map.insert(name, (addr, size));
        }
    }

    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut node_set: BTreeSet<String> = BTreeSet::new();
    let mut edges: Vec<GraphEdge> = Vec::new();

    for item in raw_cg {
        let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        node_set.insert(name.clone());

        let imports = item.get("imports")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut callees = Vec::new();
        for imp in imports {
            if let Some(callee) = imp.as_str() {
                node_set.insert(callee.to_string());
                callees.push(callee.to_string());
                edges.push(GraphEdge {
                    from: name.clone(),
                    to: callee.to_string(),
                    edge_type: "call".to_string(),
                });
            }
        }
        adjacency.insert(name, callees);
    }

    // Build nodes list
    let mut nodes = Vec::new();
    for node_id in &node_set {
        let (addr, size) = func_map.get(node_id).copied().unwrap_or((0, 0));
        let node_type = if node_id.starts_with("sym.imp.") || node_id.starts_with("reloc.") {
            "import".to_string()
        } else {
            "function".to_string()
        };
        nodes.push(GraphNode {
            id: node_id.clone(),
            label: node_id.clone(),
            node_type,
            addr,
            size,
        });
    }

    let target_str = target.unwrap_or("global").to_string();

    let rendered = match format {
        GraphFormat::Ascii | GraphFormat::Tree => {
            Some(render_ascii_tree(&adjacency, &func_map, target))
        }
        GraphFormat::Dot => {
            Some(render_dot(&nodes, &edges))
        }
        GraphFormat::Mermaid => {
            Some(render_mermaid(&nodes, &edges))
        }
        GraphFormat::Json => None,
    };



    Ok(GraphResponse {
        graph_type: "callgraph".to_string(),
        target: target_str,
        nodes,
        edges,
        rendered,
        adjacency: Some(adjacency),
    })
}

fn generate_cfg(
    driver: &R2Driver,
    target: Option<&str>,
    format: GraphFormat,
) -> Result<GraphResponse, AppError> {
    let target_str = target.ok_or_else(|| {
        AppError::InvalidArgument("Target function name or address is required for CFG graph".to_string())
    })?;

    let target_addr = driver.resolve_address(target_str)?;
    let (raw_blocks, r2_ascii_rendered) = if format == GraphFormat::Ascii {
        let cmd_afb = format!("s {:#x}; af; afbj", target_addr);
        let cmd_agf = format!("s {:#x}; agf", target_addr);
        let batch = driver.cmd_batch(&[&cmd_afb, &cmd_agf])?;
        let blocks: Vec<serde_json::Value> = R2Driver::parse_json(batch.first().map(|s| s.as_str()).unwrap_or("")).unwrap_or_default();
        let ascii = batch.get(1).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        (blocks, ascii)
    } else {
        let cmd = format!("s {:#x}; af; afbj", target_addr);
        let blocks: Vec<serde_json::Value> = driver.cmdj(&cmd)?;
        (blocks, None)
    };

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut adjacency: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for b in raw_blocks {
        let addr = b.get("addr").or_else(|| b.get("offset")).and_then(|v| v.as_u64()).unwrap_or(0);
        let size = b.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let addr_hex = format!("{:#x}", addr);

        nodes.push(GraphNode {
            id: addr_hex.clone(),
            label: addr_hex.clone(),
            node_type: "block".to_string(),
            addr,
            size,
        });

        let mut block_succs = Vec::new();

        if let Some(jump) = b.get("jump").and_then(|v| v.as_u64()).filter(|&j| j != 0 && j != u64::MAX) {
            let jump_hex = format!("{:#x}", jump);
            edges.push(GraphEdge {
                from: addr_hex.clone(),
                to: jump_hex.clone(),
                edge_type: "jump".to_string(),
            });
            block_succs.push(jump_hex);
        }

        if let Some(fail) = b.get("fail").and_then(|v| v.as_u64()).filter(|&f| f != 0 && f != u64::MAX) {
            let fail_hex = format!("{:#x}", fail);
            edges.push(GraphEdge {
                from: addr_hex.clone(),
                to: fail_hex.clone(),
                edge_type: "fail".to_string(),
            });
            block_succs.push(fail_hex);
        }

        adjacency.insert(addr_hex, block_succs);
    }

    let rendered = match format {
        GraphFormat::Ascii => {
            Some(r2_ascii_rendered.unwrap_or_else(|| render_dot(&nodes, &edges)))
        }

        GraphFormat::Dot => Some(render_dot(&nodes, &edges)),
        GraphFormat::Mermaid => Some(render_mermaid(&nodes, &edges)),
        GraphFormat::Tree => Some(render_dot(&nodes, &edges)),
        GraphFormat::Json => None,
    };

    Ok(GraphResponse {
        graph_type: "cfg".to_string(),
        target: target_str.to_string(),
        nodes,
        edges,
        rendered,
        adjacency: Some(adjacency),
    })
}

struct TreeFormatter<'a> {
    adjacency: &'a BTreeMap<String, Vec<String>>,
    func_map: &'a BTreeMap<String, (u64, u64)>,
    path_visited: HashSet<String>,
    rendered_nodes: HashSet<String>,
    output: String,
    line_count: usize,
    max_lines: usize,
    max_depth: usize,
}

impl<'a> TreeFormatter<'a> {
    fn new(
        adjacency: &'a BTreeMap<String, Vec<String>>,
        func_map: &'a BTreeMap<String, (u64, u64)>,
    ) -> Self {
        Self {
            adjacency,
            func_map,
            path_visited: HashSet::new(),
            rendered_nodes: HashSet::new(),
            output: String::new(),
            line_count: 0,
            max_lines: 2000,
            max_depth: 12,
        }
    }

    fn format_node(&mut self, node: &str, prefix: &str, is_last: bool, is_root: bool, depth: usize) {
        if self.line_count >= self.max_lines {
            if self.line_count == self.max_lines {
                self.output.push_str(&format!("{}... (output truncated at {} lines)\n", prefix, self.max_lines));
                self.line_count += 1;
            }
            return;
        }

        let addr_info = if let Some((addr, _)) = self.func_map.get(node) {
            format!(" ({:#x})", addr)
        } else {
            String::new()
        };

        if is_root {
            self.output.push_str(&format!("{}{}\n", node, addr_info));
            self.line_count += 1;
        } else {
            let branch = if is_last { "└── " } else { "├── " };
            self.output.push_str(&format!("{}{}{}{}\n", prefix, branch, node, addr_info));
            self.line_count += 1;
        }

        // 1. Cycle detection on current active path
        if self.path_visited.contains(node) {
            let child_indent = if is_last { "    " } else { "│   " };
            let cycle_prefix = format!("{}{}", prefix, child_indent);
            self.output.push_str(&format!("{}└── (cycle)\n", cycle_prefix));
            self.line_count += 1;
            return;
        }

        // 2. Global DAG deduplication: avoid re-expanding already rendered subtrees
        if !is_root && self.rendered_nodes.contains(node) {
            let child_indent = if is_last { "    " } else { "│   " };
            let ref_prefix = format!("{}{}", prefix, child_indent);
            if let Some(children) = self.adjacency.get(node) {
                if !children.is_empty() {
                    self.output.push_str(&format!("{}└── (see above)\n", ref_prefix));
                    self.line_count += 1;
                }
            }
            return;
        }

        // 3. Max depth limit
        if depth >= self.max_depth {
            let child_indent = if is_last { "    " } else { "│   " };
            let limit_prefix = format!("{}{}", prefix, child_indent);
            self.output.push_str(&format!("{}└── ...\n", limit_prefix));
            self.line_count += 1;
            return;
        }

        self.path_visited.insert(node.to_string());
        self.rendered_nodes.insert(node.to_string());

        if let Some(children) = self.adjacency.get(node) {
            let count = children.len();
            let child_indent = if is_root {
                ""
            } else if is_last {
                "    "
            } else {
                "│   "
            };
            let new_prefix = format!("{}{}", prefix, child_indent);

            for (i, child) in children.iter().enumerate() {
                let child_is_last = i == count - 1;
                self.format_node(child, &new_prefix, child_is_last, false, depth + 1);
            }
        }

        self.path_visited.remove(node);
    }
}

fn render_ascii_tree(
    adjacency: &BTreeMap<String, Vec<String>>,
    func_map: &BTreeMap<String, (u64, u64)>,
    target: Option<&str>,
) -> String {
    let mut formatter = TreeFormatter::new(adjacency, func_map);

    let roots: Vec<String> = if let Some(t) = target {
        vec![t.to_string()]
    } else {
        let mut callees = HashSet::new();
        for list in adjacency.values() {
            for c in list {
                callees.insert(c.clone());
            }
        }
        let mut top_roots: Vec<String> = adjacency.keys()
            .filter(|k| !callees.contains(*k) || *k == "main" || *k == "entry0" || *k == "_start")
            .cloned()
            .collect();

        top_roots.sort_by(|a, b| {
            let prio = |s: &str| {
                if s == "main" { 0 }
                else if s == "entry0" { 1 }
                else if s == "_start" { 2 }
                else { 3 }
            };
            prio(a).cmp(&prio(b)).then_with(|| a.cmp(b))
        });

        if top_roots.is_empty() {
            top_roots = adjacency.keys().cloned().collect();
        }

        if top_roots.len() > 50 {
            top_roots.truncate(50);
        }

        top_roots
    };

    for root in roots {
        formatter.format_node(&root, "", true, true, 0);
    }

    formatter.output.trim_end().to_string()
}

fn render_dot(nodes: &[GraphNode], edges: &[GraphEdge]) -> String {
    let mut dot = String::from("digraph G {\n  rankdir=TB;\n  node [shape=box, fontname=\"Courier\"];\n");
    for n in nodes {
        dot.push_str(&format!("  \"{}\" [label=\"{}\\n({:#x})\"];\n", n.id, n.label, n.addr));
    }
    for e in edges {
        dot.push_str(&format!("  \"{}\" -> \"{}\" [label=\"{}\"];\n", e.from, e.to, e.edge_type));
    }
    dot.push_str("}\n");
    dot
}

fn sanitize_mermaid_id(id: &str) -> String {
    let mut safe = id.replace(|c: char| !c.is_alphanumeric() && c != '_', "_");
    if safe.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        safe = format!("n_{}", safe);
    }
    safe
}

fn render_mermaid(nodes: &[GraphNode], edges: &[GraphEdge]) -> String {
    let mut m = String::from("graph TD\n");
    for n in nodes {
        let safe_id = sanitize_mermaid_id(&n.id);
        m.push_str(&format!("  {}[\"{} ({:#x})\"]\n", safe_id, n.label, n.addr));
    }
    for e in edges {
        let safe_from = sanitize_mermaid_id(&e.from);
        let safe_to = sanitize_mermaid_id(&e.to);
        m.push_str(&format!("  {} --> {}\n", safe_from, safe_to));
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_formatter_linear_tree() {
        let mut adj = BTreeMap::new();
        adj.insert("main".to_string(), vec!["foo".to_string()]);
        adj.insert("foo".to_string(), vec!["bar".to_string()]);
        adj.insert("bar".to_string(), vec![]);

        let mut func_map = BTreeMap::new();
        func_map.insert("main".to_string(), (0x1000, 32));
        func_map.insert("foo".to_string(), (0x1020, 16));
        func_map.insert("bar".to_string(), (0x1030, 8));

        let rendered = render_ascii_tree(&adj, &func_map, Some("main"));
        assert!(rendered.contains("main (0x1000)"));
        assert!(rendered.contains("└── foo (0x1020)"));
        assert!(rendered.contains("    └── bar (0x1030)"));
    }

    #[test]
    fn test_tree_formatter_cycle_detection() {
        let mut adj = BTreeMap::new();
        adj.insert("a".to_string(), vec!["b".to_string()]);
        adj.insert("b".to_string(), vec!["a".to_string()]);

        let func_map = BTreeMap::new();
        let rendered = render_ascii_tree(&adj, &func_map, Some("a"));
        assert!(rendered.contains("(cycle)"));
    }

    #[test]
    fn test_tree_formatter_dag_deduplication() {
        let mut adj = BTreeMap::new();
        adj.insert("root".to_string(), vec!["left".to_string(), "right".to_string()]);
        adj.insert("left".to_string(), vec!["shared".to_string()]);
        adj.insert("right".to_string(), vec!["shared".to_string()]);
        adj.insert("shared".to_string(), vec!["leaf".to_string()]);
        adj.insert("leaf".to_string(), vec![]);

        let func_map = BTreeMap::new();
        let rendered = render_ascii_tree(&adj, &func_map, Some("root"));
        assert!(rendered.contains("(see above)"));
    }

    #[test]
    fn test_dot_and_mermaid_rendering() {
        let nodes = vec![
            GraphNode {
                id: "main".to_string(),
                label: "main".to_string(),
                node_type: "function".to_string(),
                addr: 0x1000,
                size: 64,
            },
            GraphNode {
                id: "helper".to_string(),
                label: "helper".to_string(),
                node_type: "function".to_string(),
                addr: 0x1040,
                size: 32,
            },
        ];
        let edges = vec![GraphEdge {
            from: "main".to_string(),
            to: "helper".to_string(),
            edge_type: "call".to_string(),
        }];

        let dot = render_dot(&nodes, &edges);
        assert!(dot.contains("digraph G"));
        assert!(dot.contains("\"main\" -> \"helper\""));

        let mermaid = render_mermaid(&nodes, &edges);
        assert!(mermaid.contains("graph TD"));
        assert!(mermaid.contains("main --> helper"));
    }
}

