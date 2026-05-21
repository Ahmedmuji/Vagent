# Vagent Project Structure

## Runtime app

- `app.py` - Flask app and HTTP routes.
- `main_pipeline.py` - End-to-end RFP processing pipeline.
- `templates/` - Frontend templates.
- `scripts/` - Pipeline helpers and catalog/reference tooling.
- `scripts/vertiv/` - Vertiv-only extraction, retrieval, and reference injection logic.

## Data

- `data/product_catalogs/` - Active product catalogs used by matching.
- `data/navigation/` - Navigation/TOC indexes used for admin-guide references.
- `data/reference_excel/` - Reference Excel inputs and sample compliance sheets.
- `data/scraper_outputs/` - Raw or intermediate scraper outputs that are not active catalogs.
- `data/Complete RFPs/`, `data/Extracted*`, `output/` - Runtime/generated processing artifacts.

## Docs and archive

- `docs/` - Project notes and pipeline documentation.
- `docs/reports/` - Generated reports such as SRF/comparison documents.
- `archive/` - Old versions or snapshots kept for comparison, not used by the app.
