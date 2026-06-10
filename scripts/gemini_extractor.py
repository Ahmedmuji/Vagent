import os
import json
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class GeminiExtractionError(RuntimeError):
    """Raised when Gemini extraction fails for a specific PDF chunk."""


def _call_gemini_once(client, model_name, prompt, chunk_index):
    try:
        try:
            return client.models.generate_content(
                model=model_name,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )
        except TypeError:
            return client.models.generate_content(
                model=model_name,
                contents=prompt,
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

def convert_pdf_to_markdown(pdf_path):
    """Convert a local PDF into Markdown using MarkItDown."""
    try:
        from markitdown import MarkItDown
    except ImportError as exc:
        raise GeminiExtractionError(
            "MarkItDown is not installed. Install it with: pip install 'markitdown[pdf]'"
        ) from exc

    converter = MarkItDown(enable_plugins=False)
    result = converter.convert(pdf_path)
    markdown = (
        getattr(result, "text_content", None)
        or getattr(result, "markdown", None)
        or str(result)
    )
    markdown = str(markdown or "").strip()
    if not markdown:
        raise GeminiExtractionError(f"MarkItDown returned empty Markdown for {pdf_path}.")
    return markdown


def chunk_markdown(markdown, max_chars=None):
    """Split Markdown into Gemini-sized chunks while trying to keep tables/sections intact."""
    max_chars = int(max_chars or os.getenv("MARKITDOWN_CHUNK_CHARS", "35000"))
    if len(markdown) <= max_chars:
        return [markdown]

    chunks = []
    remaining = markdown
    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining.strip())
            break
        window = remaining[:max_chars]
        split_at = max(
            window.rfind("\n# "),
            window.rfind("\n## "),
            window.rfind("\n\n"),
            window.rfind("\n|"),
        )
        if split_at < max_chars * 0.45:
            split_at = max_chars
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].lstrip()
    return [chunk for chunk in chunks if chunk]


def build_extraction_prompt(markdown_chunk, chunk_index, total_chunks):
    return (
        "You are extracting technical requirements from a Markdown transcription of an RFP PDF. "
        "Extract EVERY single piece of information present in this Markdown chunk. "
        "Do not summarize. Do not omit any paragraphs, bullets, table rows, or continuation rows. "
        "Return only a valid JSON object with a 'sheets' key containing a list of objects. "
        "Do not include markdown, commentary, explanations, or text outside the JSON object.\n\n"

        f"Markdown chunk {chunk_index} of {total_chunks}:\n"
        "```markdown\n"
        f"{markdown_chunk}\n"
        "```\n\n"

        "1. FOR TABLES (CRITICAL STRUCTURAL RULES):\n"
        "   - Preserve the EXACT column structure and row order represented in the Markdown.\n"
        "   - Do NOT merge adjacent columns.\n"
        "   - Extract EVERY row in technical/compliance/requirements tables, even when the table is long or continues across chunks/pages.\n"
        "   - Do NOT stop after the first few rows of a technical requirements table. Rows such as throughput, sessions, interfaces, storage, HA, licensing, support, and all later continuation rows are mandatory.\n"
        "   - Preserve all subsection headers and category labels inside tables.\n"
        "   - Category labels must be extracted as separate rows.\n"
        "   - For EACH row, include a 'row_type' field: use \"section\" for category/subsection labels and \"data\" for normal requirement rows.\n"
        "   - Empty cells MUST be represented as an empty string \"\".\n"
        "   - Schema for 'rows': [{\"row_type\": \"section\"|\"data\", \"data\": [\"cell1\", \"cell2\", ...], \"metadata\": {...}}, ...]\n"
        "   - Schema for 'sheets': [{\"title\": \"Table Name\", \"headers\": [...], \"sheet_metadata\": {...}, \"rows\": [...]}]\n\n"

        "2. FOR PARAGRAPHS / NARRATIVE TEXT:\n"
        "   - Every paragraph, bullet point, or sentence that is NOT in a table MUST be captured.\n"
        "   - Group these into a sheet titled 'General Content' or use the section heading as the title.\n"
        "   - Use [\"Description\"] as the single header for these text-only sheets.\n"
        "   - Each paragraph should be a separate row: [\"The full paragraph text...\"]\n\n"

        "3. SEMANTIC REQUIREMENT METADATA:\n"
        "   - Metadata is secondary. If metadata is hard, still extract the row and use simple/unknown metadata rather than omitting or merging the row.\n"
        "   - Do NOT generate product URLs, datasheet URLs, SKUs, product models, page references, or citations.\n"
        "   - Do NOT append a References column or Admin Guide citation columns.\n"
        "   - Every row MUST include a metadata object, but it may be minimal. Use null for unknown scalar values, [] for empty lists, and false only when clearly false.\n"
        "   - If uncertain whether a row needs a later product/admin reference, set requires_reference=true, reference_needed_confidence='low', and row_role='uncertain'. Downstream validation will decide.\n"
        "   - If a sheet says things like 'minimum requirements per firewall appliance' or 'required specifications per device', treat it as ONE product/platform with many spec rows: first actual technical spec row is product_anchor; later technical rows are spec_continuation using the same product_group_id.\n"
        "   - For sheet_metadata include product_layout ('single_product'|'multiple_products'|'no_product_requirements'|'unknown'), product_block_count, and notes.\n"
        "   - Use this compact metadata schema for every row:\n"
        "     {\n"
        "       \"is_procurement_requirement\": true|false,\n"
        "       \"requires_reference\": true|false,\n"
        "       \"reference_needed_confidence\": \"high\"|\"medium\"|\"low\"|\"none\",\n"
        "       \"row_role\": \"product_anchor\"|\"spec_continuation\"|\"section\"|\"unrelated\"|\"uncertain\",\n"
        "       \"provider_hint\": \"fortinet\"|\"juniper\"|\"vertiv\"|\"unknown\",\n"
        "       \"device_category\": \"ngfw\"|\"datacenter_switch\"|\"access_switch\"|\"router\"|\"adc\"|\"waf\"|\"centralized_management\"|\"siem_soc\"|\"ndr\"|\"endpoint_security\"|\"identity_access\"|\"pam\"|\"sdn_automation\"|\"ups\"|\"battery_energy_storage\"|\"rack\"|\"rack_accessory\"|\"pdu\"|\"power_distribution\"|\"transfer_switch\"|\"busway\"|\"cooling\"|\"cooling_control\"|\"monitoring\"|\"kvm\"|\"serial_console\"|\"software\"|\"unknown\",\n"
        "       \"product_group_id\": \"PROD_001\"|null,\n"
        "       \"product_group_primary_row\": true|false,\n"
        "       \"is_product_spec_continuation\": true|false,\n"
        "       \"specs\": [{\"name\": \"ssl_vpn_concurrent_users\", \"value\": 17000, \"unit\": \"users\", \"raw_text\": \"17,000 SSL-VPN concurrent users\"}],\n"
        "       \"detected_specs\": {},\n"
        "       \"fortinet_feature_candidates\": [\"HA\", \"SSL_VPN\", \"FIREWALL_POLICY\"]\n"
        "     }\n"
        "   - fortinet_feature_candidates MUST use only this controlled vocabulary when relevant: HA, SSL_VPN, IPSEC_VPN, FIREWALL_POLICY, IPS, ANTIVIRUS, WEB_FILTERING, APPLICATION_CONTROL, SD_WAN, ROUTING, INTERFACE, ADMINISTRATION, LOGGING_REPORTING, AUTHENTICATION, CERTIFICATE, USER_IDENTITY, TRAFFIC_SHAPING, VPN, SYSTEM_SETTINGS.\n"
        "   - Put every measurable requirement into specs, but never omit a row just because you cannot classify its specs.\n\n"

        "4. OUTPUT RULES:\n"
        "   - Return ONLY valid JSON.\n"
        "   - The first character of the response MUST be { and the last character MUST be }.\n"
        "   - Do not wrap the JSON in markdown fences.\n"
        "   - Include the 'sheets' root key.\n"
        "   - Ensure visual order is preserved."
    )

def get_technical_data_from_gemini(pdf_path, model_name="gemini-3-flash-preview", chunk_output_dir=None):
    """Extract structured requirements by converting the PDF to Markdown before calling Gemini."""
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise ValueError("GEMINI_API_KEY not found in .env file.")

    from google import genai
    client = genai.Client(api_key=api_key)

    print(f"Converting PDF to Markdown with MarkItDown: {pdf_path}...")
    markdown = convert_pdf_to_markdown(pdf_path)
    if chunk_output_dir:
        os.makedirs(chunk_output_dir, exist_ok=True)
        markdown_path = os.path.join(chunk_output_dir, "markitdown.md")
        with open(markdown_path, "w", encoding="utf-8") as f:
            f.write(markdown)
        print(f"MarkItDown Markdown saved to {markdown_path}")

    markdown_chunks = chunk_markdown(markdown)
    all_sheets = []

    for chunk_index, markdown_chunk in enumerate(markdown_chunks, start=1):
        print(f"Requesting extraction from {model_name} for Markdown chunk {chunk_index}/{len(markdown_chunks)}...")
        prompt = build_extraction_prompt(markdown_chunk, chunk_index, len(markdown_chunks))
        response = _call_gemini_once(client, model_name, prompt, chunk_index)

        raw_text = response.text or ""
        if not raw_text.strip():
            raise GeminiExtractionError(
                f"Gemini returned an empty response for Markdown chunk {chunk_index}."
            )
        json_str = extract_json_from_text(raw_text)

        try:
            chunk_data = json.loads(json_str)

            if chunk_output_dir:
                os.makedirs(chunk_output_dir, exist_ok=True)
                chunk_file_path = os.path.join(chunk_output_dir, f"chunk_{chunk_index}.json")
                with open(chunk_file_path, "w", encoding="utf-8") as f:
                    json.dump(chunk_data, f, indent=4)
                print(f"Chunk {chunk_index} saved to {chunk_file_path}")

            if isinstance(chunk_data, dict) and "sheets" in chunk_data:
                all_sheets.extend(chunk_data["sheets"])
            elif isinstance(chunk_data, list):
                all_sheets.extend(chunk_data)
            else:
                all_sheets.append(chunk_data)
        except json.JSONDecodeError as e:
            if chunk_output_dir:
                os.makedirs(chunk_output_dir, exist_ok=True)
                raw_file_path = os.path.join(chunk_output_dir, f"chunk_{chunk_index}_raw_response.txt")
                with open(raw_file_path, "w", encoding="utf-8") as f:
                    f.write(raw_text or "")
                md_chunk_path = os.path.join(chunk_output_dir, f"chunk_{chunk_index}_markitdown.md")
                with open(md_chunk_path, "w", encoding="utf-8") as f:
                    f.write(markdown_chunk)
                print(f"Raw chunk response saved to {raw_file_path}")
            preview = (raw_text or "")[:500].replace("\n", "\\n")
            raise GeminiExtractionError(
                f"Gemini returned invalid JSON for Markdown chunk {chunk_index}: {e}. Raw preview: {preview!r}"
            ) from e

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
