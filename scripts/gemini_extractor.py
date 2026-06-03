import os
import json
import re
import base64
import requests
from dotenv import load_dotenv
from pypdf import PdfReader, PdfWriter

# Load environment variables
load_dotenv()


class GeminiExtractionError(RuntimeError):
    """Raised when Gemini extraction fails for a specific PDF chunk."""


def _call_gemini_once(client, model_name, prompt, uploaded_file, chunk_index):
    try:
        try:
            return client.models.generate_content(
                model=model_name,
                contents=[prompt, uploaded_file],
                config={"response_mime_type": "application/json"},
            )
        except TypeError:
            return client.models.generate_content(
                model=model_name,
                contents=[prompt, uploaded_file],
            )
    except Exception as exc:
        message = str(exc) or exc.__class__.__name__
        print(f"Gemini extraction failed for chunk {chunk_index}: {message}")
        raise GeminiExtractionError(
            f"Gemini extraction failed for chunk {chunk_index}. Last error: {message}"
        ) from exc

def extract_json_from_text(text):
    """Cleans the model's response to extract only the JSON part and repairs common errors."""
    stripped = (text or "").strip().lstrip("\ufeff")
    candidates = []
    json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', stripped, re.IGNORECASE)
    if json_match:
        candidates.append(json_match.group(1).strip())
    candidates.append(stripped)

    decoder = json.JSONDecoder()
    for candidate in candidates:
        if not candidate:
            continue
        starts = [idx for idx in (candidate.find("{"), candidate.find("[")) if idx >= 0]
        for start in sorted(starts):
            try:
                _, end = decoder.raw_decode(candidate[start:])
                return candidate[start:start + end].strip()
            except json.JSONDecodeError:
                continue
    return stripped

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
                "Return only a valid JSON object with a 'sheets' key containing a list of objects. "
                "Do not include markdown, commentary, explanations, or text outside the JSON object.\n\n"
            
            "1. FOR TABLES (CRITICAL STRUCTURAL RULES):\n"
            "   - Preserve the EXACT column structure and row order from the source.\n"
            "   - Do NOT merge adjacent columns.\n"
            "   - Preserve all subsection headers and category labels inside tables.\n"
            "   - Category labels (rows spanning multiple columns) must be extracted as separate rows.\n"
            "   - Decide whether each extracted sheet/table contains a single product/platform requirement block or multiple product/platform requirement blocks.\n"
            "   - For every sheet object, include a top-level 'sheet_metadata' object with: product_block_count, product_layout ('single_product'|'multiple_products'|'no_product_requirements'|'unknown'), and notes.\n"
            "   - For every sheet object, include a top-level 'product_blocks' list. Each item MUST include product_group_id, product_label, start_row_index, end_row_index, primary_row_index, device_category, and evidence.\n"
            "   - Row indexes in product_blocks are zero-based indexes into that sheet's rows array.\n"
            "   - If one firewall/switch/router/UPS/rack/etc. has its specs spread across many rows, all those rows MUST share the same product_group_id and only the first/most descriptive row should be primary.\n"
            "   - If a table contains multiple products, create a separate product_group_id for each product and set the primary_row_index to the row where that product starts.\n"
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
            "   - First preserve/transcribe the table or paragraph exactly. Metadata is a lightweight annotation only; never rewrite row text to make classification easier.\n"
            "   - Do NOT generate product URLs, datasheet URLs, SKUs, product models, page references, or citations.\n"
            "   - Do NOT append a References column or Admin Guide citation columns.\n"
            "   - Every row MUST include a metadata object. Use null for unknown scalar values, [] for no lists, and false only when a boolean is clearly false.\n"
            "   - If uncertain whether a row needs a later product/admin reference, set requires_reference=true, reference_needed_confidence='low', and let downstream validation decide. Use requires_reference=false only for rows that are clearly headings, commercial/legal/admin text, or non-product narrative.\n"
            "   - Use row_role as the primary product-boundary signal:\n"
            "     * product_anchor = the one row where a product reference should later be placed.\n"
            "     * spec_continuation = extra specs for the same product block; no reference should be placed on that row.\n"
            "     * section = category/subsection header row.\n"
            "     * unrelated = not a technical product/capability requirement.\n"
            "     * uncertain = likely technical, but product boundary is unclear.\n"
            "   - product_group_id MUST be shared by all rows describing one physical/logical product. In a single-product table, usually only one row is product_anchor and all other technical rows are spec_continuation. In a multi-product table, each product block gets exactly one product_anchor.\n"
            "   - Keep legacy compatibility fields aligned with row_role: product_anchor means product_group_primary_row=true, group_primary_row=true, product_group_start=true, is_product_spec_continuation=false. spec_continuation means product_group_primary_row=false, group_primary_row=false, product_group_start=false, is_product_spec_continuation=true.\n"
            "   - The metadata object MUST use this schema for every row:\n"
            "     {\n"
            "       \"is_procurement_requirement\": true|false,\n"
            "       \"procurement_intent\": \"new_hardware_procurement\"|\"existing_environment_description\"|\"operational_policy\"|\"administrative_text\"|\"compliance_requirement\"|\"technical_capability_requirement\"|\"unknown\",\n"
            "       \"requires_reference\": true|false,\n"
            "       \"reference_needed_confidence\": \"high\"|\"medium\"|\"low\"|\"none\",\n"
            "       \"row_role\": \"product_anchor\"|\"spec_continuation\"|\"section\"|\"unrelated\"|\"uncertain\",\n"
            "       \"provider_hint\": \"fortinet\"|\"juniper\"|\"vertiv\"|\"unknown\",\n"
            "       \"device_category\": \"ngfw\"|\"datacenter_switch\"|\"access_switch\"|\"router\"|\"adc\"|\"waf\"|\"centralized_management\"|\"siem_soc\"|\"ndr\"|\"endpoint_security\"|\"identity_access\"|\"pam\"|\"sdn_automation\"|\"ups\"|\"battery_energy_storage\"|\"rack\"|\"rack_accessory\"|\"pdu\"|\"power_distribution\"|\"transfer_switch\"|\"busway\"|\"cooling\"|\"cooling_control\"|\"monitoring\"|\"kvm\"|\"serial_console\"|\"software\"|\"unknown\",\n"
            "       \"device_subcategory\": \"datacenter_firewall\"|\"branch_firewall\"|\"core_switch\"|\"leaf_switch\"|\"access_switch\"|\"edge_router\"|\"software_platform\"|\"lithium_ion_battery\"|\"precision_cooling\"|\"row_cooling\"|\"rack_pdu\"|\"server_rack\"|\"rack_accessory\"|\"unknown\",\n"
            "       \"technical_requirement_type\": \"throughput\"|\"capacity\"|\"interface\"|\"availability\"|\"security_feature\"|\"management\"|\"licensing\"|\"support\"|\"policy\"|\"power\"|\"cooling\"|\"rack_physical\"|\"other\"|\"unknown\",\n"
            "       \"requirement_group_id\": \"REQ_001\"|null,\n"
            "       \"group_primary_row\": true|false,\n"
            "       \"product_group_id\": \"PROD_001\"|null,\n"
            "       \"product_group_primary_row\": true|false,\n"
            "       \"product_group_start\": true|false,\n"
            "       \"is_product_spec_continuation\": true|false,\n"
            "       \"sheet_product_layout\": \"single_product\"|\"multiple_products\"|\"no_product_requirements\"|\"unknown\",\n"
            "       \"contains_quantitative_specs\": true|false,\n"
            "       \"specs\": [{\"name\": \"ssl_vpn_concurrent_users\", \"value\": 17000, \"unit\": \"users\", \"raw_text\": \"17,000 SSL-VPN concurrent users\"}],\n"
            "       \"detected_specs\": {\n"
            "         \"ngfw_throughput_gbps\": number|null,\n"
            "         \"firewall_throughput_gbps\": number|null,\n"
            "         \"ips_throughput_gbps\": number|null,\n"
            "         \"threat_protection_gbps\": number|null,\n"
            "         \"ssl_tls_inspection_gbps\": number|null,\n"
            "         \"ipsec_vpn_throughput_gbps\": number|null,\n"
            "         \"ssl_vpn_gbps\": number|null,\n"
            "         \"ssl_vpn_concurrent_users\": integer|null,\n"
            "         \"scalable_ssl_vpn_concurrent_users\": integer|null,\n"
            "         \"switching_capacity_tbps\": number|null,\n"
            "         \"switching_capacity_gbps\": number|null,\n"
            "         \"concurrent_sessions\": integer|null,\n"
            "         \"connections_per_second\": integer|null,\n"
            "         \"cps\": integer|null,\n"
            "         \"interfaces_1g\": integer|null,\n"
            "         \"interfaces_10g\": integer|null,\n"
            "         \"interfaces_25g\": integer|null,\n"
            "         \"interfaces_40g\": integer|null,\n"
            "         \"interfaces_100g\": integer|null,\n"
            "         \"ports\": integer|null,\n"
            "         \"policies\": integer|null,\n"
            "         \"storage_tb\": number|null,\n"
            "         \"storage_gb\": number|null,\n"
            "         \"power_capacity_kw\": number|null,\n"
            "         \"power_capacity_kva\": number|null,\n"
            "         \"cooling_capacity_kw\": number|null,\n"
            "         \"rack_units\": integer|null,\n"
            "         \"static_load_kg\": number|null,\n"
            "         \"dynamic_load_kg\": number|null,\n"
            "         \"outlet_count\": integer|null,\n"
            "         \"backup_runtime_minutes\": number|null,\n"
            "         \"voltage_v\": number|null,\n"
            "         \"phase_count\": integer|null,\n"
            "         \"redundant_power\": true|false\n"
            "       },\n"
            "       \"fortinet_feature_candidates\": [\"HA\", \"SSL_VPN\", \"FIREWALL_POLICY\"]\n"
            "     }\n"
            "   - fortinet_feature_candidates MUST use only this controlled vocabulary when relevant: HA, SSL_VPN, IPSEC_VPN, FIREWALL_POLICY, IPS, ANTIVIRUS, WEB_FILTERING, APPLICATION_CONTROL, SD_WAN, ROUTING, INTERFACE, ADMINISTRATION, LOGGING_REPORTING, AUTHENTICATION, CERTIFICATE, USER_IDENTITY, TRAFFIC_SHAPING, VPN, SYSTEM_SETTINGS.\n"
            "   - Put every measurable requirement into specs even if detected_specs has no matching field. Use the most specific detected_specs field when one exists; do not force Vertiv/power/cooling/rack specs into Fortinet/network fields.\n\n"

            "4. OUTPUT RULES:\n"
            "   - Return ONLY valid JSON.\n"
            "   - The first character of the response MUST be { and the last character MUST be }.\n"
            "   - Do not wrap the JSON in markdown fences.\n"
            "   - Include the 'sheets' root key.\n"
                "   - Ensure visual order is preserved."
            )

            print(f"Requesting extraction from {model_name} for chunk {chunk_index + 1}...")
            response = _call_gemini_once(
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
                preview = (raw_text or "")[:500].replace("\n", "\\n")
                raise GeminiExtractionError(
                    f"Gemini returned invalid JSON for chunk {chunk_index + 1}: {e}. Raw preview: {preview!r}"
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
