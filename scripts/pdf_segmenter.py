import os
import argparse
from pypdf import PdfReader, PdfWriter

def extract_pages(input_pdf, output_pdf, start_page, end_page):
    """
    Extracts a range of pages from a PDF and saves them to a new file.
    :param input_pdf: Path to source PDF
    :param output_pdf: Path to save the extracted PDF
    :param start_page: Start page number (1-indexed)
    :param end_page: End page number (1-indexed, inclusive)
    """
    reader = PdfReader(input_pdf)
    writer = PdfWriter()

    # Convert 1-indexed to 0-indexed
    # Note: range is inclusive of end_page
    for page_num in range(start_page - 1, end_page):
        if page_num < len(reader.pages):
            writer.add_page(reader.pages[page_num])
        else:
            print(f"Warning: Page {page_num + 1} exceeds document length.")
            break

    os.makedirs(os.path.dirname(output_pdf), exist_ok=True)
    with open(output_pdf, "wb") as f:
        writer.write(f)
    
    print(f"SUCCESS: Pages {start_page}-{end_page} extracted to {output_pdf}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract a page range from a PDF.")
    parser.add_argument("--input", help="Source PDF path", required=True)
    parser.add_argument("--output", help="Output PDF name (in data folder)", default="segment.pdf")
    parser.add_argument("--start", type=int, help="Start page (1-indexed)", required=True)
    parser.add_argument("--end", type=int, help="End page (1-indexed)", required=True)

    args = parser.parse_args()

    # Ensure output is in the data folder
    output_path = os.path.join("data", args.output)
    
    extract_pages(args.input, output_path, args.start, args.end)
