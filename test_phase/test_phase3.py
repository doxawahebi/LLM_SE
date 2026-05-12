import os
import json
from phases.phase3_verifier import verify_vulnerability

# source_path = "/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c"
source_path = "/home/cks/Project/SE-LLM-project/juliet-test-suite-c/testcases/CWE122_Heap_Based_Buffer_Overflow/s01/CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_fscanf_02.cpp"
poc_path = "/home/cks/Project/SE-LLM-project/poc.bin"

try:
    result = verify_vulnerability(source_path, poc_path)
    print("PHASE3 RESULT:")
    print(json.dumps(result, indent=2))
except Exception as e:
    print("PHASE3 ERROR:", str(e))
