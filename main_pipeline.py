import os
import json
import sys
import argparse


# Ensure the script can import from scripts folder
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts"))

from gemini_extractor import get_technical_data_from_gemini
from local_section_detector import detect_requirements as local_detect_requirements
from pdf_segmenter import extract_pages
from json_to_excel import create_formatted_excel
from admin_guide_enricher import FortinetAdminGuideReferenceEnricher
from pdf_admin_metadata import build_admin_guide_metadata_index
from reference_injector import inject_hardware_references
from fortinet.reference_injector import inject_fortinet_references
from juniper.reference_injector import inject_juniper_references
from vertiv.reference_injector import inject_vertiv_references
from cost_estimator import AbortedByUser, confirm_execution, estimate_cost

FORTINET_REFERENCE_PROVIDERS = {"fortinet", "fortinet-rag", "fortinet-rules", "deterministic"}

def get_unique_dir(parent_dir, base_name):
    """Generates a unique directory path by appending a counter if it exists."""
    dir_path = os.path.join(parent_dir, base_name)
    if not os.path.exists(dir_path):
        return dir_path
    
    counter = 1
    while True:
        new_path = os.path.join(parent_dir, f"{base_name}_{counter}")
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def get_unique_path(parent_dir, filename):
    """Generates a unique file path by appending a counter before the extension if it exists."""
    name, ext = os.path.splitext(filename)
    file_path = os.path.join(parent_dir, filename)
    if not os.path.exists(file_path):
        return file_path
    
    counter = 1
    while True:
        new_path = os.path.join(parent_dir, f"{name}_{counter}{ext}")
        if not os.path.exists(new_path):
            return new_path
        counter += 1

def toc_index_has_pdf_links(toc_index_path):
    if not os.path.exists(toc_index_path):
        return False
    try:
        with open(toc_index_path, "r", encoding="utf-8") as f:
            index = json.load(f)
        if not index or not isinstance(index, list):
            return False
        sample = [entry for entry in index[:25] if isinstance(entry, dict)]
        if not sample:
            return False
        # Check if it has either web URLs or PDF uris
        has_web_url = any(isinstance(entry.get("url"), str) for entry in sample)
        if has_web_url:
            return True
            
        return all(
            isinstance(entry.get("page"), int)
            and entry.get("anchor") == f"#page={entry.get('page')}"
            and isinstance(entry.get("pdf_uri"), str)
            and f"#page={entry.get('page')}" in entry.get("pdf_uri", "")
            for entry in sample
        )
    except Exception:
        return False

def get_project_paths(project_root):
    return {
        "input_dir": os.path.join(project_root, "data", "Complete RFPs"),
        "extracted_pdf_dir": os.path.join(project_root, "data", "Extracted Requirements Section"),
        "json_results_dir": os.path.join(project_root, "data", "Extracted JSON Results"),
        "excel_results_dir": os.path.join(project_root, "data", "Extracted Excel Results"),
        "admin_guide_pdf_path": os.path.join(project_root, "data", "Reference dataset", "FortiOS-7.6.6-Administration_Guide.pdf"),
        "toc_index_path": os.path.join(project_root, "data", "navigation", "fortinet_sidebar_flat.json"),
    }

def ensure_runtime_dirs(paths):
    for key in ("input_dir", "extracted_pdf_dir", "json_results_dir", "excel_results_dir"):
        os.makedirs(paths[key], exist_ok=True)
    os.makedirs(os.path.dirname(paths["toc_index_path"]), exist_ok=True)
    os.makedirs(os.path.dirname(paths["admin_guide_pdf_path"]), exist_ok=True)

def prepare_admin_guide_index(project_root, skip_enrichment=False):
    paths = get_project_paths(project_root)
    if skip_enrichment:
        print("Skipping Admin Guide enrichment because skip_enrichment is enabled.")
        return None, paths["admin_guide_pdf_path"]
        
    # If the pre-computed TOC index exists, proceed even if the PDF is missing
    if os.path.exists(paths["toc_index_path"]):
        print(f"Using Admin Guide TOC index: {paths['toc_index_path']}")
        return paths["toc_index_path"], paths["admin_guide_pdf_path"]
        
    # If TOC is missing, try to build it from the PDF
    if os.path.exists(paths["admin_guide_pdf_path"]):
        print("Extracting Admin Guide PDF metadata for enrichment...")
        flat_index = build_admin_guide_metadata_index(paths["admin_guide_pdf_path"], paths["toc_index_path"])
        print(f"  Flat index saved: {paths['toc_index_path']} ({len(flat_index)} entries)")
        return paths["toc_index_path"], paths["admin_guide_pdf_path"]
        
    print("WARNING: Admin Guide enrichment cannot start.")
    print(f"  Missing TOC index: {paths['toc_index_path']}")
    print(f"  Missing Admin Guide PDF: {paths['admin_guide_pdf_path']}")
    print("  Run git pull to restore data/navigation/fortinet_sidebar_flat.json, or place the Admin Guide PDF at the path above so the TOC can be rebuilt.")
    return None, paths["admin_guide_pdf_path"]

def recover_admin_guide_index(project_root, toc_index_path=None, admin_guide_pdf_path=None):
    """Recover Fortinet Admin Guide metadata when a caller passed a stale or missing TOC path."""
    paths = get_project_paths(project_root)
    preferred_toc_path = paths["toc_index_path"]
    preferred_pdf_path = paths["admin_guide_pdf_path"]
    toc_index_path = toc_index_path or preferred_toc_path
    admin_guide_pdf_path = admin_guide_pdf_path or preferred_pdf_path

    if toc_index_path and os.path.exists(toc_index_path):
        return toc_index_path, admin_guide_pdf_path

    if os.path.exists(preferred_toc_path):
        print(f"Recovered Admin Guide TOC index: {preferred_toc_path}")
        return preferred_toc_path, admin_guide_pdf_path

    pdf_path = admin_guide_pdf_path if os.path.exists(admin_guide_pdf_path) else preferred_pdf_path
    if os.path.exists(pdf_path):
        print("Recovering Admin Guide TOC index from PDF...")
        flat_index = build_admin_guide_metadata_index(pdf_path, preferred_toc_path)
        print(f"  Flat index saved: {preferred_toc_path} ({len(flat_index)} entries)")
        return preferred_toc_path, pdf_path

    return toc_index_path, admin_guide_pdf_path

def process_pdf_section(filename, input_path, start_page, end_page, extracted_pdf_dir, json_results_dir, excel_results_dir, toc_index_path=None, admin_guide_pdf_path=None, model_name=None, reference_provider="fortinet"):
    base_name = os.path.splitext(filename)[0].replace("_Requirements", "")
    print(f"\n--- Processing: {base_name} pages {start_page}-{end_page} ---")

    pdf_json_dir = get_unique_dir(json_results_dir, base_name)
    pdf_excel_dir = get_unique_dir(excel_results_dir, base_name)
    os.makedirs(pdf_json_dir, exist_ok=True)
    os.makedirs(pdf_excel_dir, exist_ok=True)

    extracted_pdf_path = os.path.join(extracted_pdf_dir, f"{base_name}_Requirements.pdf")
    extracted_pdf_path = get_unique_path(extracted_pdf_dir, os.path.basename(extracted_pdf_path))
    extract_pages(input_path, extracted_pdf_path, int(start_page), int(end_page))

    print(f"Sending to Gemini for table extraction (saving chunks to {pdf_json_dir})...")

    # ------------------------------------------------------------------
    # COST GATE: estimate API cost and require operator confirmation
    # before making any LLM calls.
    # ------------------------------------------------------------------
    cost_info = estimate_cost(extracted_pdf_path, model_name=model_name)
    confirm_execution(cost_info)

    technical_data = get_technical_data_from_gemini(extracted_pdf_path, model_name=cost_info["model"], chunk_output_dir=pdf_json_dir)

    reference_provider = (reference_provider or "fortinet").strip().lower()
    if reference_provider == "vertiv":
        print("Resolving hardware references from Vertiv RAG catalog...")
        technical_data, hardware_stats = inject_vertiv_references(technical_data)
    elif reference_provider == "juniper":
        print("Resolving hardware references from Juniper RAG catalog...")
        technical_data, hardware_stats = inject_juniper_references(technical_data)
    elif reference_provider in {"fortinet", "fortinet-rag"}:
        print("Resolving hardware references from Fortinet RAG catalog...")
        technical_data, hardware_stats = inject_fortinet_references(technical_data)
    elif reference_provider in {"fortinet-rules", "deterministic"}:
        print("Resolving hardware references from deterministic Fortinet product catalogs...")
        technical_data, hardware_stats = inject_hardware_references(technical_data)
    else:
        print("Resolving hardware references from Fortinet RAG catalog...")
        technical_data, hardware_stats = inject_fortinet_references(technical_data)
    print(f"  Hardware reference stats: {hardware_stats}")

    json_filename = f"{base_name}.json"
    json_path = get_unique_path(pdf_json_dir, json_filename)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(technical_data, f, indent=4)

    excel_filename = f"{base_name}.xlsx"
    excel_path = get_unique_path(pdf_excel_dir, excel_filename)
    if not create_formatted_excel(technical_data, excel_path):
        raise RuntimeError(f"Excel generation failed for {base_name}")

    final_excel_path = excel_path
    enrichment_stats = None
    if reference_provider in FORTINET_REFERENCE_PROVIDERS:
        project_root = os.path.dirname(os.path.abspath(__file__))
        toc_index_path, admin_guide_pdf_path = recover_admin_guide_index(
            project_root,
            toc_index_path,
            admin_guide_pdf_path,
        )

    if reference_provider in FORTINET_REFERENCE_PROVIDERS and toc_index_path and os.path.exists(toc_index_path):
        print("Enriching with Fortinet Admin Guide references...")
        enriched_filename = f"{base_name}_enriched_with_admin_guide_references.xlsx"
        enriched_path = os.path.join(pdf_excel_dir, enriched_filename)

        enricher = FortinetAdminGuideReferenceEnricher(
            workbook_path=excel_path,
            toc_index_path=toc_index_path,
            admin_guide_pdf_path=admin_guide_pdf_path,
        )
        enricher.load_workbook()
        enricher.load_toc_index()
        enricher.build_embedding_index()
        enricher.enrich_workbook()
        enricher.save_output(enriched_path)
        final_excel_path = enriched_path
        enrichment_stats = enricher.stats
        print(f"  Enriched Excel: {enriched_path}")
        print(f"  Enrichment stats: {enrichment_stats}")
    elif reference_provider in FORTINET_REFERENCE_PROVIDERS:
        print("  Skipping Admin Guide enrichment (no TOC index available).")
    else:
        print(f"  Skipping Fortinet Admin Guide enrichment for {reference_provider} reference provider.")

    return {
        "base_name": base_name,
        "extracted_pdf_path": extracted_pdf_path,
        "json_path": json_path,
        "excel_path": excel_path,
        "final_excel_path": final_excel_path,
        "hardware_stats": hardware_stats,
        "enrichment_stats": enrichment_stats,
    }

def process_single_file(filename, input_path, extracted_pdf_dir, json_results_dir, excel_results_dir, toc_index_path=None, admin_guide_pdf_path=None, model_name=None, reference_provider="fortinet"):

    """Orchestrates the full extraction for a single PDF file."""
    base_name = os.path.splitext(filename)[0].replace("_Requirements", "")
    print(f"\n--- Processing: {base_name} ---")
    
    try:
        # 1. Detect Range & Segment (Local)
        result = local_detect_requirements(input_path)
        
        outputs = process_pdf_section(
            filename,
            input_path,
            result["start_page"],
            result["end_page"],
            extracted_pdf_dir,
            json_results_dir,
            excel_results_dir,
            toc_index_path,
            admin_guide_pdf_path,
            model_name,
            reference_provider,
        )
        print(f"SUCCESS: Generated reports for {base_name}:")
        print(f"  JSON:  {outputs['json_path']}")
        print(f"  Excel: {outputs['final_excel_path']}")

    except Exception as e:
        print(f"ERROR processing {base_name}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Run the end-to-end RFP extraction pipeline.")
    parser.add_argument("--input", help="Path to a specific PDF to process. If omitted, runs batch mode.")
    parser.add_argument("--skip-enrichment", action="store_true",
                        help="Skip the Fortinet Admin Guide enrichment step.")
    parser.add_argument("--model", default=None,
                        help="Gemini model to use for extraction and cost estimation.")
    parser.add_argument("--reference-provider", choices=["fortinet", "fortinet-rag", "fortinet-rules", "deterministic", "vertiv"], default="fortinet",
                        help="Product reference provider to use for hardware references.")
    args = parser.parse_args()

    print("=== STARTING RFP EXTRACTION PIPELINE ===\n")
    
    # Define project paths
    project_root = os.path.dirname(os.path.abspath(__file__))
    input_dir = os.path.join(project_root, "data", "Complete RFPs")
    extracted_pdf_dir = os.path.join(project_root, "data", "Extracted Requirements Section")
    json_results_dir = os.path.join(project_root, "data", "Extracted JSON Results")
    excel_results_dir = os.path.join(project_root, "data", "Extracted Excel Results")
    
    os.makedirs(extracted_pdf_dir, exist_ok=True)
    os.makedirs(json_results_dir, exist_ok=True)
    os.makedirs(excel_results_dir, exist_ok=True)
    
    # Prepare TOC flat index for Admin Guide enrichment
    toc_index_path = None
    admin_guide_pdf_path = os.path.join(project_root, "data", "Reference dataset", "FortiOS-7.6.6-Administration_Guide.pdf")
    if not args.skip_enrichment:
        toc_flat = os.path.join(project_root, "output", "toc_flat_index.json")
        
        if os.path.exists(admin_guide_pdf_path):
            if not toc_index_has_pdf_links(toc_flat):
                print("Extracting Admin Guide PDF metadata for enrichment...")
                flat_index = build_admin_guide_metadata_index(admin_guide_pdf_path, toc_flat)
                print(f"  Flat index saved: {toc_flat} ({len(flat_index)} entries)")
            toc_index_path = toc_flat
        else:
            print(f"WARNING: Admin Guide PDF not found: {admin_guide_pdf_path}")
            print("  Skipping Admin Guide enrichment.")
    
    if args.input:
        # SINGLE FILE MODE
        if not os.path.exists(args.input):
            print(f"Error: File not found: {args.input}")
            return
        filename = os.path.basename(args.input)
        process_single_file(filename, args.input, extracted_pdf_dir, json_results_dir, excel_results_dir, toc_index_path, admin_guide_pdf_path, args.model, args.reference_provider)
    else:
        # BATCH MODE
        if not os.path.exists(input_dir):
            print(f"Error: Input directory not found: {input_dir}")
            return
        
        files = [f for f in os.listdir(input_dir) if f.lower().endswith(".pdf")]
        print(f"BATCH MODE: Found {len(files)} files in {input_dir}")
        
        for filename in files:
            input_path = os.path.join(input_dir, filename)
            process_single_file(filename, input_path, extracted_pdf_dir, json_results_dir, excel_results_dir, toc_index_path, admin_guide_pdf_path, args.model, args.reference_provider)

    print("\n=== PIPELINE COMPLETE ===")
    print(f"JSON Results:  {json_results_dir}")
    print(f"Excel Results: {excel_results_dir}")

if __name__ == "__main__":
    main()
