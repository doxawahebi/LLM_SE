import os
import subprocess

def verify_vulnerability(source_path: str, poc_path: str) -> dict:
    # We assume the source_path is the main file or can be compiled directly
    # For a real project, this might require a Makefile or specific build commands
    # For this system, we use clang -fsanitize=address
    
    out_binary = source_path + ".asan.out"
    compile_cmd = ["gcc", "-fsanitize=address", "-g", "-O0", "-I/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcasesupport", "-DINCLUDEMAIN", source_path, "/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcasesupport/io.c", "-o", out_binary]
    
    comp_result = subprocess.run(compile_cmd, capture_output=True, text=True)
    if comp_result.returncode != 0:
        raise RuntimeError(f"ASAN Compilation failed:\n{comp_result.stderr}")
        
    # Execute binary with poc.bin as stdin or argument
    # We will pass it as stdin as it's common for PoCs
    with open(poc_path, "rb") as f:
        poc_data = f.read()
        
    run_result = subprocess.run([out_binary], input=poc_data, capture_output=True)
    
    # Parse ASAN output
    asan_trace = run_result.stderr.decode('utf-8', errors='ignore')
    is_vulnerable = "ERROR: AddressSanitizer" in asan_trace
    
    rca_summary = "No vulnerability triggered."
    if is_vulnerable:
        # Extract the first line of the ASAN trace
        for line in asan_trace.splitlines():
            if "ERROR: AddressSanitizer" in line:
                rca_summary = line.strip()
                break
                
    return {
        "verified": is_vulnerable,
        "rca_summary": rca_summary,
        "full_trace": asan_trace
    }
