import json
import os
import tree_sitter_c as tsc
from tree_sitter import Language, Parser

def parse_sarif_and_extract_slice(sarif_path: str, source_dir: str) -> dict:
    with open(sarif_path, 'r') as f:
        sarif_data = json.load(f)
    
    # Very basic extraction of first result
    # In a real scenario we might process multiple results
    try:
        run = sarif_data['runs'][0]
        result = run['results'][0]
        location = result['locations'][0]['physicalLocation']
        uri = location['artifactLocation']['uri']
        start_line = location['region']['startLine']
        cwe_id = result.get('ruleId', 'Unknown')
    except (KeyError, IndexError) as e:
        raise ValueError(f"Failed to parse SARIF file: {e}")
        
    file_path = os.path.join(source_dir, uri)
    print("file_path", file_path)
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Source file not found: {file_path}")
        
    with open(file_path, 'r') as f:
        source_code = f.read()
        
    # Setup tree-sitter
    C_LANGUAGE = Language(tsc.language())
    parser = Parser(C_LANGUAGE)
    tree = parser.parse(bytes(source_code, "utf8"))
    
    # Find the function definition containing start_line
    # We'll use a simple tree walk
    def traverse(node):
        if node.type == 'function_definition':
            # Check if start_line is within this node
            # tree-sitter lines are 0-indexed, SARIF is 1-indexed
            if node.start_point[0] <= start_line - 1 <= node.end_point[0]:
                return node
        for child in node.children:
            res = traverse(child)
            if res:
                return res
        return None
        
    target_node = traverse(tree.root_node)
    
    if target_node is None:
        raise ValueError(f"Could not find function definition at line {start_line} in {file_path}")
        
    slice_code = source_code[target_node.start_byte:target_node.end_byte]
    
    # Extract function name
    declarator = None
    for child in target_node.children:
        if child.type == 'function_declarator':
            declarator = child
            break
            
    func_name = "unknown_function"
    if declarator:
        for child in declarator.children:
            if child.type == 'identifier':
                func_name = source_code[child.start_byte:child.end_byte]
                break
                
    return {
        "file_path": file_path,
        "function_name": func_name,
        "start_line": target_node.start_point[0] + 1,
        "end_line": target_node.end_point[0] + 1,
        "cwe_id": cwe_id,
        "slice": slice_code
    }
