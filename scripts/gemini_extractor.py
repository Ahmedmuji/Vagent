import os
import json
import re
import time
import base64
import requests
from dotenv import load_dotenv
from pypdf import PdfReader, PdfWriter

# Load environment variables
load_dotenv()


class GeminiExtractionError(RuntimeError):
    """Raised when Gemini extraction fails for a specific PDF chunk."""


def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _call_gemini_with_retries(client, model_name, prompt, uploaded_file, chunk_index):
    max_attempts = max(1, _env_int("GEMINI_EXTRACTOR_MAX_RETRIES", 3))
    base_delay = max(1, _env_int("GEMINI_EXTRACTOR_RETRY_DELAY_SECONDS", 8))
    last_error = None

    for attempt in range(1, max_attempts + 1):
        try:
            return client.models.generate_content(
                model=model_name,
                contents=[prompt, uploaded_file],
            )
        except Exception as exc:
            last_error = exc
            message = str(exc) or exc.__class__.__name__
            print(
                f"Gemini extraction failed for chunk {chunk_index} "
                f"(attempt {attempt}/{max_attempts}): {message}"
            )
            if attempt >= max_attempts:
                break
            time.sleep(base_delay * attempt)

    raise GeminiExtractionError(
        f"Gemini extraction failed for chunk {chunk_index} after {max_attempts} attempts. "
        f"Last error: {last_error}"
    ) from last_error

def extract_json_from_text(text):
    """Cleans the model's response to extract only the JSON part and repairs common errors."""
    # Find the JSON block
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', text)
    if json_match:
        return json_match.group(1).strip()
    return text.strip()

def chunk_pdf(pdf_path, max_pages=10):
    """Splits a PDF into chunks of up to `max_pages` pages."""
    reader = PdfReader(pdf_path)
    total_pages = len(reader.pages)
    if total_pages <= max_pages:
        return [pdf_path]
        
    chunk_paths = []
    base_name = os.path.splitext(os.path.basename(pdf_path))[0]
    chunk_dir = os.path.join(os.path.dirname(pdf_path), f"{base_name}_chunks")
    os.makedirs(chunk_dir, exist_ok=True)
    
    for start_idx in range(0, total_pages, max_pages):
        end_idx = min(start_idx + max_pages, total_pages)
        writer = PdfWriter()
        for i in range(start_idx, end_idx):
            writer.add_page(reader.pages[i])
            
        chunk_path = os.path.join(chunk_dir, f"{base_name}_chunk_{start_idx//max_pages + 1}.pdf")
        with open(chunk_path, "wb") as f:
            writer.write(f)
        chunk_paths.append(chunk_path)
        
    return chunk_paths

def get_technical_data_from_gemini(pdf_path, model_name="gemini-3-flash-preview", chunk_output_dir=None):
    """PART 1: The API Call (Data Extraction via Google GenAI)"""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in .env file.")

    from google import genai
    client = genai.Client(api_key=api_key)

    chunk_paths = chunk_pdf(pdf_path, max_pages=10)
    all_sheets = []

    for chunk_index, current_pdf_path in enumerate(chunk_paths):
        print(f"Reading file chunk {chunk_index + 1}/{len(chunk_paths)}: {current_pdf_path}...")
        
        uploaded_file = None
        try:
            # Upload the file chunk using the official SDK
            print(f"Uploading chunk {chunk_index + 1} to Google Gemini...")
            uploaded_file = client.files.upload(file=current_pdf_path)

            prompt = (
                "Extract EVERY single piece of information from the attached technical document. "
                "Do not summarize. Do not omit any paragraphs or narrative text. "
                "The output must be a JSON object with a 'sheets' key containing a list of objects.\n\n"
            
            "1. FOR TABLES (CRITICAL STRUCTURAL RULES):\n"
            "   - Preserve the EXACT column structure and row order from the source.\n"
            "   - Do NOT merge adjacent columns.\n"
            "   - Preserve all subsection headers and category labels inside tables.\n"
            "   - Category labels (rows spanning multiple columns) must be extracted as separate rows.\n"
            "   - For EACH row, include a 'row_type' field: use \"section\" for category/subsection labels and \"data\" for normal requirement rows.\n"
            "   - Empty cells MUST be represented as an empty string \"\".\n"
            "   - Schema for 'rows': [{\"row_type\": \"section\"|\"data\", \"data\": [\"cell1\", \"cell2\", ...], \"metadata\": {...}}, ...]\n"
            "   - Schema for 'sheets': [{\"title\": \"Table Name\", \"headers\": [...], \"rows\": [...]}]\n\n"

            "2. FOR PARAGRAPHS / NARRATIVE TEXT:\n"
            "   - Every paragraph, bullet point, or sentence that is NOT in a table MUST be captured.\n"
            "   - Group these into a sheet titled 'General Content' or use the section heading as the title.\n"
            "   - Use [\"Description\"] as the single header for these text-only sheets.\n"
            "   - Each paragraph should be a separate row: [\"The full paragraph text...\"]\n\n"
            
            "3. SEMANTIC REQUIREMENT METADATA:\n"
            "   - Gemini MUST perform semantic extraction and classification for every row.\n"
            "   - Preserve the original table/narrative structure exactly, then append a metadata object to each row.\n"
            "   - Do NOT generate product URLs, datasheet URLs, SKUs, product models, page references, or citations.\n"
            "   - Do NOT append a References column.\n"
            "   - Do NOT append Admin Guide citation columns.\n"
            "   - If a row clearly contains measurable technical requirements, include the exact measurable values in the row text without changing the table schema.\n"
            "   - The metadata object MUST use this schema for every row:\n"
            "     {\n"
            "       \"is_procurement_requirement\": true|false,\n"
            "       \"procurement_intent\": \"new_hardware_procurement\"|\"existing_environment_description\"|\"operational_policy\"|\"administrative_text\"|\"compliance_requirement\"|\"technical_capability_requirement\"|\"unknown\",\n"
            "       \"requires_reference\": true|false,\n"
            "       \"device_category\": \"ngfw\"|\"datacenter_switch\"|\"access_switch\"|\"adc\"|\"waf\"|\"centralized_management\"|\"siem_soc\"|\"ndr\"|\"endpoint_security\"|\"identity_access\"|\"pam\"|\"routing\"|\"sdn_automation\"|\"unknown\",\n"
            "       \"device_subcategory\": \"datacenter_firewall\"|\"branch_firewall\"|\"core_switch\"|\"leaf_switch\"|\"access_switch\"|\"edge_router\"|\"software_platform\"|\"unknown\",\n"
            "       \"technical_requirement_type\": \"throughput\"|\"capacity\"|\"interface\"|\"availability\"|\"security_feature\"|\"management\"|\"licensing\"|\"support\"|\"policy\"|\"other\"|\"unknown\",\n"
            "       \"requirement_group_id\": \"REQ_NGFW_001\"|null,\n"
            "       \"group_primary_row\": true|false,\n"
            "       \"contains_quantitative_specs\": true|false,\n"
            "       \"detected_specs\": {\n"
            "         \"ngfw_throughput_gbps\": number|null,\n"
            "         \"ips_throughput_gbps\": number|null,\n"
            "         \"threat_protection_gbps\": number|null,\n"
            "         \"ssl_tls_inspection_gbps\": number|null,\n"
            "         \"ssl_vpn_gbps\": number|null,\n"
            "         \"switching_capacity_tbps\": number|null,\n"
            "         \"concurrent_sessions\": integer|null,\n"
            "         \"cps\": integer|null,\n"
            "         \"interfaces_1g\": integer|null,\n"
            "         \"interfaces_10g\": integer|null,\n"
            "         \"interfaces_25g\": integer|null,\n"
            "         \"interfaces_40g\": integer|null,\n"
            "         \"interfaces_100g\": integer|null,\n"
            "         \"policies\": integer|null,\n"
            "         \"storage_tb\": number|null\n"
            "       },\n"
            "       \"fortinet_feature_candidates\": [\"HA\", \"SSL VPN\", \"Firewall Policies\"]\n"
            "     }\n"
            "   - Use null for unknown scalar values, [] for no feature candidates, and false for unavailable booleans.\n"
            "   - requirement_group_id MUST be shared by rows that describe the same appliance/platform requirement block.\n"
            "   - group_primary_row MUST be true only for the most representative row in each requirement_group_id block.\n"
            "   - Set requires_reference=true only when a deterministic product or Fortinet Admin Guide reference should later be attached.\n\n"

            "4. OUTPUT RULES:\n"
            "   - Return ONLY valid JSON.\n"
            "   - Include the 'sheets' root key.\n"
                "   - Ensure visual order is preserved."
            )

            print(f"Requesting extraction from {model_name} for chunk {chunk_index + 1}...")
            response = _call_gemini_with_retries(
                client,
                model_name,
                prompt,
                uploaded_file,
                chunk_index + 1,
            )

            raw_text = response.text or ""
            if not raw_text.strip():
                raise GeminiExtractionError(
                    f"Gemini returned an empty response for chunk {chunk_index + 1}."
                )
            json_str = extract_json_from_text(raw_text)

            try:
                chunk_data = json.loads(json_str)

                # Save individual chunk JSON if output directory is provided
                if chunk_output_dir:
                    os.makedirs(chunk_output_dir, exist_ok=True)
                    chunk_file_path = os.path.join(chunk_output_dir, f"chunk_{chunk_index + 1}.json")
                    with open(chunk_file_path, "w", encoding="utf-8") as f:
                        json.dump(chunk_data, f, indent=4)
                    print(f"Chunk {chunk_index + 1} saved to {chunk_file_path}")

                if isinstance(chunk_data, dict) and "sheets" in chunk_data:
                    all_sheets.extend(chunk_data["sheets"])
                elif isinstance(chunk_data, list):
                    all_sheets.extend(chunk_data)
                else:
                    all_sheets.append(chunk_data)
            except json.JSONDecodeError as e:
                if chunk_output_dir:
                    os.makedirs(chunk_output_dir, exist_ok=True)
                    raw_file_path = os.path.join(chunk_output_dir, f"chunk_{chunk_index + 1}_raw_response.txt")
                    with open(raw_file_path, "w", encoding="utf-8") as f:
                        f.write(raw_text or "")
                    print(f"Raw chunk response saved to {raw_file_path}")
                raise GeminiExtractionError(
                    f"Gemini returned invalid JSON for chunk {chunk_index + 1}: {e}"
                ) from e
        finally:
            # Clean up the file from Google's servers after processing or failure.
            if uploaded_file is not None:
                try:
                    client.files.delete(name=uploaded_file.name)
                except Exception as e:
                    print(f"Warning: Could not delete uploaded file {uploaded_file.name}: {e}")

    return {"sheets": all_sheets}

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Extract technical data from a PDF using Gemini (via OpenRouter).")
    parser.add_argument("--input", help="Source PDF path", default=os.path.join("data", "technical_requirements_55_68.pdf"))
    parser.add_argument("--output", help="Output JSON path", default=os.path.join("output", "extraction_cache.json"))
    parser.add_argument("--model", help="Gemini model name", default="google/gemini-3.1-pro-preview")

    args = parser.parse_args()

    try:
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        extracted_data = get_technical_data_from_gemini(args.input, model_name=args.model)
        
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(extracted_data, f, indent=4)
        
        print(f"SUCCESS! Extraction saved to: {args.output}")
    except Exception as e:
        print(f"An error occurred: {e}")
