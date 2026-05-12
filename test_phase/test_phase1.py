# cd /home/cks/Project/SE-LLM-project
# PYTHONPATH=/home/cks/Project/SE-LLM-project python test1/test_phase1.py

import json
from phases.phase1_parser import parse_sarif_and_extract_slice

try:
    res = parse_sarif_and_extract_slice('./test1/cwe122_results.sarif', '/home/cks/Project/SE-LLM-project')
    print("PHASE1 OUTPUT:")
    print(json.dumps(res, indent=2))
except Exception as e:
    print("Error:", e)
