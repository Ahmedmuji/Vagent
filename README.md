# RFP Technical Extraction Pipeline 🚀

A high-performance, AI-driven pipeline for isolating technical requirements from RFP (Request for Proposal) PDF documents and transforming them into enriched, actionable Excel workbooks.

![UI Mockup](https://raw.githubusercontent.com/username/repo/main/docs/ui-preview.png) *(Placeholder for your actual screenshot)*

## 🌟 Key Features

- **Heuristic Section Detection**: Instantly identifies technical requirement sections in large PDFs without consuming API credits.
- **AI-Powered Table Extraction**: Leverages Google Gemini AI to accurately parse complex, nested technical tables into structured JSON.
- **Deterministic Hardware Injection**: Cross-references extracted items with product catalogs for verified hardware identification.
- **Fortinet Admin Guide Enrichment**: Automatically embeds deep-link citations from the FortiOS Administration Guide using semantic search and embedding matching.
- **Modern Web Interface**: A premium, JS-driven Glassmorphism UI for effortless file uploads and real-time processing feedback.
- **Batch Processing**: CLI support for processing entire directories of RFP documents in one go.

## 🛠 Technology Stack

- **Backend**: Python 3.x, Flask
- **AI**: Google Gemini Pro (via Vertex AI / Generative AI SDK)
- **PDF Processing**: PyPDF, PDFPlumber
- **Data Handling**: Pandas, OpenPyXL
- **Frontend**: Vanilla JavaScript (ES6+), CSS3 (Glassmorphism), HTML5

## 📋 Prerequisites

- Python 3.9+
- A Google Cloud Project with Gemini API access
- An API Key (configured in `.env`)

## 🚀 Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/your-username/rfp-extractor.git
cd rfp-extractor
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
Create a `.env` file in the root directory:
```env
GOOGLE_API_KEY=your_gemini_api_key_here
FLASK_SECRET_KEY=your_secret_key
MAX_UPLOAD_MB=200
```

### 4. Run the Web UI
```bash
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

### 5. Run via CLI (Batch Mode)
Place your PDFs in `data/Complete RFPs/` and run:
```bash
python main_pipeline.py
```

## 📁 Project Structure

- `app.py`: Flask web server and API endpoints.
- `main_pipeline.py`: Main orchestrator for end-to-end processing.
- `scripts/`:
    - `local_section_detector.py`: Heuristic-based PDF segmentation.
    - `gemini_extractor.py`: AI table extraction logic.
    - `admin_guide_enricher.py`: Reference injection and citation logic.
    - `json_to_excel.py`: Formatted Excel generation.
- `templates/`: Modern JS-driven frontend.
- `data/`: Input PDFs, product catalogs, and reference datasets.
- `output/`: Generated indexes and cached metadata.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*Developed for Premier Systems - Automating Technical Excellence.*
