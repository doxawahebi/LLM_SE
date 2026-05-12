import os
import subprocess
from google import genai

def generate_and_run_harness(metadata: dict, target_binary: str) -> str:
    prompt = f"""
You are an expert security researcher. I need a Python micro-harness using `angr` to perform symbolic execution and generate a Proof of Concept (PoC) binary file for a vulnerability.

Target binary: {target_binary}
Vulnerable Function: {metadata['function_name']}
CWE: {metadata['cwe_id']}
File: {metadata['file_path']}

Source Code Slice:
```c
{metadata['slice']}
```

Generate a complete, self-contained Python script using `angr` that will:
1. Load the target binary.
2. Setup the state to start executing at `{metadata['function_name']}`.
3. Symbolize the arguments to explore paths.
4. Add constraints to avoid path explosion.
5. Search for a crashing state or memory corruption.
6. Dump the crashing input to `poc.bin`.
7. Exit with 0 on success.

Output ONLY valid Python code inside a ```python block.
"""
    print("prompt : " , prompt)
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY environment variable is not set")
        
    client = genai.Client(api_key=api_key)
    
    response = client.models.generate_content(
        model='gemini-2.5-flash',
        contents=prompt,
    )
    
    # Extract Python code
    text = response.text
    if "```python" in text:
        code = text.split("```python")[1].split("```")[0].strip()
    elif "```" in text:
        code = text.split("```")[1].split("```")[0].strip()
    else:
        code = text.strip()
        
    harness_path = "angr_harness.py"
    with open(harness_path, "w") as f:
        f.write(code)
        
    # Execute the harness
    poc_path = "poc.bin"
    if os.path.exists(poc_path):
        os.remove(poc_path)
        
    result = subprocess.run(["python3", harness_path], capture_output=True, text=True)
    
    if not os.path.exists(poc_path):
        raise RuntimeError(f"Harness execution failed to produce poc.bin. \nStdout: {result.stdout}\nStderr: {result.stderr}")
        
    return os.path.abspath(poc_path)
