# RFP Technical Extraction Pipeline

This pipeline automates the extraction of technical requirements and tables from RFP PDF documents. It uses a hybrid approach: local heuristics for high-precision section isolation and Gemini AI for complex table extraction.

---

## Master Command
To run the **entire end-to-end pipeline** (Detection → Segmentation → AI Extraction):

```powershell
python main_pipeline.py
```
*This command orchestrates all runtime modules in a single sequence.*

---

## Web Frontend
To run the upload UI:

```powershell
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Upload an RFP PDF and optionally enter the technical requirements start/end page range. If the range is left blank, the app automatically detects the technical requirements section before returning the final Excel file for download.

---

## Modular Commands

### 1. Local Section Detection
Identify the technical requirement page range (Start/End) without using API credits.
```powershell
python scripts/local_section_detector.py --input "path/to/rfp.pdf"
```

### 2. PDF Segmentation
Extract a specific page range from a large PDF into a clean, standalone document.
```powershell
python scripts/pdf_segmenter.py --input "source.pdf" --start 55 --end 68 --output "cleaned_specs.pdf"
```

### 3. Gemini Table Extraction
Extract structural technical tables from the isolated PDF into clean JSON.
```powershell
python scripts/gemini_extractor.py --input "data/Extracted Requirements Section/cleaned_specs.pdf"
```

---

## 📁 Project Structure
- **`scripts/`**: Core logic and automation modules.
- **`data/Complete RFPs/`**: Place your original RFP files here.
- **`data/Extracted Requirements Section/`**: Cleaned technical segments are saved here.
- **`data/product_catalogs/`**: Deterministic hardware catalogs used for reference injection.
- **`data/Reference dataset/`**: Fortinet Admin Guide PDF used for citation enrichment.
- **`output/`**: Generated Admin Guide indexes and other runtime outputs.

---

## 🛠 Troubleshooting
- **ImportErrors**: Ensure you are running from the project root directory.
- **PDF Extraction**: If detection is off, check `output/batch_detection_report.json` to see the text snippets used for matching.
