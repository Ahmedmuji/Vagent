import os
import uuid

# Fix for HuggingFace tokenizers crashing/deadlocking in Gunicorn's forked worker processes
os.environ["TOKENIZERS_PARALLELISM"] = "false"
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, url_for
from pypdf import PdfReader
from werkzeug.utils import secure_filename

from main_pipeline import ensure_runtime_dirs, get_project_paths, local_detect_requirements, prepare_admin_guide_index, process_pdf_section
from cost_estimator import AbortedByUser, estimate_cost, get_supported_models, resolve_model_pricing


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_EXTENSIONS = {".pdf"}

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "vagent-local-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_MB", "200")) * 1024 * 1024


class UserInputError(Exception):
    pass


def allowed_pdf(filename):
    return Path(filename).suffix.lower() in UPLOAD_EXTENSIONS


def parse_page_range(start_page_raw, end_page_raw, total_pages):
    start_page_raw = str(start_page_raw or "").strip()
    end_page_raw = str(end_page_raw or "").strip()
    if not start_page_raw and not end_page_raw:
        return None
    if not start_page_raw or not end_page_raw:
        raise UserInputError("Enter both start and end pages, or leave both blank for automatic detection.")
    try:
        start_page = int(start_page_raw)
        end_page = int(end_page_raw)
    except (TypeError, ValueError):
        raise UserInputError("Start page and end page must be valid numbers.")
    if start_page < 1 or end_page < 1:
        raise UserInputError("Page numbers must be greater than zero.")
    if end_page < start_page:
        raise UserInputError("End page must be greater than or equal to start page.")
    if end_page > total_pages:
        raise UserInputError(f"End page cannot exceed the PDF page count ({total_pages}).")
    return start_page, end_page


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/models", methods=["GET"])
def list_models():
    return jsonify({"models": get_supported_models()})


@app.route("/reference_pdf", methods=["GET"])
def serve_reference_pdf():
    paths = get_project_paths(PROJECT_ROOT)
    pdf_path = paths["admin_guide_pdf_path"]
    if os.path.exists(pdf_path):
        # conditional=True enables HTTP Range Requests, allowing the browser to fetch only the exact page bytes
        return send_file(pdf_path, conditional=True)
    return "Admin Guide PDF not found on server.", 404


@app.route("/estimate_cost", methods=["POST"])
def estimate_cost_route():
    """
    Pre-flight cost estimation endpoint.
    Accepts the same file upload as /process, saves the file, estimates
    the API cost, and returns JSON — WITHOUT starting any LLM processing.
    The browser uses this to show a cost confirmation dialog.
    """
    uploaded_file = request.files.get("rfp_file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "Please upload an RFP PDF."}), 400
    if not allowed_pdf(uploaded_file.filename):
        return jsonify({"error": "Only PDF files are supported."}), 400

    paths = get_project_paths(PROJECT_ROOT)
    ensure_runtime_dirs(paths)
    model_name = request.form.get("model_name")
    selected_model = resolve_model_pricing(model_name)

    original_name = secure_filename(uploaded_file.filename) or "uploaded_rfp.pdf"
    run_id = uuid.uuid4().hex[:8]
    base_name, ext = os.path.splitext(original_name)
    stored_name = f"{base_name}_{run_id}{ext}"
    input_path = os.path.join(paths["input_dir"], stored_name)
    uploaded_file.save(input_path)

    try:
        total_pages = len(PdfReader(input_path).pages)
        page_range = parse_page_range(
            request.form.get("start_page"),
            request.form.get("end_page"),
            total_pages,
        )
        if page_range is None:
            detected = local_detect_requirements(input_path)
            start_page = detected["start_page"]
            end_page = detected["end_page"]
        else:
            start_page, end_page = page_range
        # Extract just the relevant pages so the estimate matches what will be processed
        from pdf_segmenter import extract_pages as _extract
        import tempfile, pathlib
        tmp_path = os.path.join(paths["extracted_pdf_dir"], f"cost_check_{run_id}.pdf")
        _extract(input_path, tmp_path, int(start_page), int(end_page))

        cost_info = estimate_cost(tmp_path, model_name=selected_model["id"])
        # Clean up the temp file
        try:
            os.remove(tmp_path)
        except OSError:
            pass

        return jsonify({
            "stored_name": stored_name,   # client passes this back to /process
            "original_name": original_name,
            "model_name": selected_model["id"],
            "cost": cost_info,
        })
    except Exception as exc:
        app.logger.exception("Cost estimation failed")
        return jsonify({"error": str(exc)}), 500


@app.route("/process", methods=["POST"])
def process_upload():
    paths = get_project_paths(PROJECT_ROOT)
    ensure_runtime_dirs(paths)
    model_name = request.form.get("model_name")
    selected_model = resolve_model_pricing(model_name)
    reference_provider = (request.form.get("reference_provider") or "fortinet").strip().lower()
    if reference_provider not in {"fortinet", "vertiv"}:
        return jsonify({"error": "Invalid reference provider selected."}), 400

    # Two-step flow: /estimate_cost already saved the file; client passes stored_name back.
    pre_stored_name = request.form.get("stored_name")
    if pre_stored_name:
        stored_name = secure_filename(pre_stored_name)
        original_name = request.form.get("original_name") or stored_name
        input_path = os.path.join(paths["input_dir"], stored_name)
        if not os.path.exists(input_path):
            return jsonify({"error": "Pre-uploaded file not found. Please re-upload."}), 400
    else:
        # Classic single-step upload
        uploaded_file = request.files.get("rfp_file")
        if not uploaded_file or not uploaded_file.filename:
            return jsonify({"error": "Please upload an RFP PDF."}), 400
        if not allowed_pdf(uploaded_file.filename):
            return jsonify({"error": "Only PDF files are supported."}), 400
        original_name = secure_filename(uploaded_file.filename) or "uploaded_rfp.pdf"
        run_id = uuid.uuid4().hex[:8]
        base_name, ext = os.path.splitext(original_name)
        stored_name = f"{base_name}_{run_id}{ext}"
        input_path = os.path.join(paths["input_dir"], stored_name)
        uploaded_file.save(input_path)

    try:
        total_pages = len(PdfReader(input_path).pages)
        page_range = parse_page_range(
            request.form.get("start_page"),
            request.form.get("end_page"),
            total_pages,
        )
        if page_range is None:
            detected = local_detect_requirements(input_path)
            start_page = detected["start_page"]
            end_page = detected["end_page"]
        else:
            start_page, end_page = page_range
        skip_enrichment = request.form.get("skip_enrichment") == "on" or reference_provider != "fortinet"
        toc_index_path, admin_guide_pdf_path = prepare_admin_guide_index(
            PROJECT_ROOT,
            skip_enrichment=skip_enrichment,
        )
        outputs = process_pdf_section(
            stored_name,
            input_path,
            start_page,
            end_page,
            paths["extracted_pdf_dir"],
            paths["json_results_dir"],
            paths["excel_results_dir"],
            toc_index_path,
            admin_guide_pdf_path,
            selected_model["id"],
            reference_provider,
        )
        final_excel_path = outputs["final_excel_path"]
        download_name = f"{Path(original_name).stem}_enriched_requirements.xlsx"
        return send_file(final_excel_path, as_attachment=True, download_name=download_name)
    except UserInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except AbortedByUser as exc:
        return jsonify({"error": f"Processing cancelled: {exc}"}), 202
    except Exception as exc:
        app.logger.exception("Pipeline processing failed")
        return jsonify({"error": f"Pipeline processing failed: {str(exc)}"}), 500


@app.route("/recent_downloads", methods=["GET"])
def get_recent_downloads():
    paths = get_project_paths(PROJECT_ROOT)
    excel_dir = paths["excel_results_dir"]
    if not os.path.exists(excel_dir):
        return jsonify({"files": []})

    stored_name = secure_filename(request.args.get("stored_name") or "")
    run_base = Path(stored_name).stem if stored_name else ""

    files = []
    for root, _, filenames in os.walk(excel_dir):
        for f in filenames:
            if f.endswith(".xlsx"):
                filepath = os.path.join(root, f)
                rel_path = os.path.relpath(filepath, excel_dir)
                rel_parts = Path(rel_path).parts
                if run_base and (not rel_parts or rel_parts[0] != run_base):
                    continue
                stat = os.stat(filepath)
                files.append({
                    "name": f,
                    "path": rel_path.replace("\\", "/"),
                    "mtime": stat.st_mtime,
                    "size": stat.st_size
                })
    
    # Sort by newest first. For a specific run, return the newest generated workbook only.
    files.sort(key=lambda x: x["mtime"], reverse=True)
    return jsonify({"files": files[:1] if run_base else []})


@app.route("/download/<path:filename>", methods=["GET"])
def download_file(filename):
    paths = get_project_paths(PROJECT_ROOT)
    excel_dir = paths["excel_results_dir"]
    # Prevent directory traversal
    safe_path = os.path.abspath(os.path.join(excel_dir, filename))
    if not safe_path.startswith(os.path.abspath(excel_dir)):
        return "Access denied", 403
        
    if os.path.exists(safe_path):
        return send_file(safe_path, as_attachment=True)
    return "File not found", 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
