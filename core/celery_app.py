from celery import Celery
import os

redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
celery_app = Celery(
    'vuln_tasks',
    broker=redis_url,
    backend=redis_url
)

celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
)

@celery_app.task(bind=True, name='core.celery_app.run_vulnerability_analysis')
def run_vulnerability_analysis(self, sarif_path: str, source_dir: str, target_binary: str):
    from phases.phase1_parser import parse_sarif_and_extract_slice
    from phases.phase2_symbex import generate_and_run_harness
    from phases.phase3_verifier import verify_vulnerability
    
    # Phase 1: Static Analysis (CodeQL + Tree-sitter)
    self.update_state(state='PHASE1', meta={'status': 'Parsing SARIF and extracting C code slice...'})
    try:
        metadata = parse_sarif_and_extract_slice(sarif_path, source_dir)
    except Exception as e:
        return {"error": f"Phase 1 failed: {str(e)}"}
        
    # Phase 2: Harness Generation & Symbolic Execution
    self.update_state(state='PHASE2', meta={'status': 'Generating harness via LLM and running angr...'})
    try:
        poc_path = generate_and_run_harness(metadata, target_binary)
    except Exception as e:
        return {"error": f"Phase 2 failed: {str(e)}"}
        
    # Phase 3: ASAN Verifier & RCA
    self.update_state(state='PHASE3', meta={'status': 'Compiling with ASAN and running verifier...'})
    try:
        # Assuming metadata contains 'file_path' which is the absolute path to the vulnerable source
        vuln_file_path = metadata.get('file_path', source_dir)
        rca_report = verify_vulnerability(vuln_file_path, poc_path)
    except Exception as e:
        return {"error": f"Phase 3 failed: {str(e)}"}
        
    return {
        "status": "completed",
        "poc_path": poc_path,
        "rca_report": rca_report,
        "metadata": metadata
    }
