import os
import uuid
from pathlib import Path

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, url_for
from pypdf import PdfReader
from werkzeug.utils import secure_filename

from main_pipeline import ensure_runtime_dirs, get_project_paths, local_detect_requirements, prepare_admin_guide_index, process_pdf_section


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


@app.route("/reference_pdf", methods=["GET"])
def serve_reference_pdf():
    paths = get_project_paths(PROJECT_ROOT)
    pdf_path = paths["admin_guide_pdf_path"]
    if os.path.exists(pdf_path):
        return send_file(pdf_path)
    return "Admin Guide PDF not found on server.", 404


@app.route("/process", methods=["POST"])
def process_upload():
    uploaded_file = request.files.get("rfp_file")
    if not uploaded_file or not uploaded_file.filename:
        return jsonify({"error": "Please upload an RFP PDF."}), 400
    if not allowed_pdf(uploaded_file.filename):
        return jsonify({"error": "Only PDF files are supported."}), 400

    paths = get_project_paths(PROJECT_ROOT)
    ensure_runtime_dirs(paths)

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
        skip_enrichment = request.form.get("skip_enrichment") == "on"
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
        )
        final_excel_path = outputs["final_excel_path"]
        download_name = f"{Path(original_name).stem}_enriched_requirements.xlsx"
        return send_file(final_excel_path, as_attachment=True, download_name=download_name)
    except UserInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("Pipeline processing failed")
        return jsonify({"error": f"Pipeline processing failed: {str(exc)}"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
