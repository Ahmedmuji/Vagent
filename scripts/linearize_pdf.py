#!/usr/bin/env python3
"""
linearize_pdf.py
================
This script converts a standard PDF into a "Linearized" PDF (Fast Web View).
Linearized PDFs have their internal table of contents moved to the very beginning
of the file. This allows web browsers to instantly download and jump to specific
pages using HTTP Byte-Range requests, without having to download the entire
massive file first.

Usage:
    python scripts/linearize_pdf.py "data/Reference dataset/FortiOS-7.6.6-Administration_Guide.pdf"
"""

import sys
import os
import time
import subprocess
import shutil

def linearize_pdf(input_path: str, output_path: str = None):
    if not os.path.exists(input_path):
        print(f"Error: Input file '{input_path}' not found.")
        sys.exit(1)

    # Check if qpdf is installed
    if not shutil.which("qpdf"):
        print("Error: 'qpdf' is required for linearization but is not installed.")
        print("Please install it by running the following command on your server:")
        print("    sudo apt-get install qpdf -y")
        sys.exit(1)

    if output_path is None:
        directory = os.path.dirname(input_path)
        filename = os.path.basename(input_path)
        name, ext = os.path.splitext(filename)
        output_path = input_path
        backup_path = os.path.join(directory, f"{name}_backup{ext}")
        
        print(f"Creating backup at: {backup_path}")
        os.rename(input_path, backup_path)
        input_path_to_read = backup_path
    else:
        input_path_to_read = input_path

    print(f"Reading PDF: {input_path_to_read}")
    start_time = time.time()
    
    try:
        print(f"Saving linearized PDF to: {output_path}")
        print("This may take a minute or two for large PDFs...")
        
        # Use qpdf to linearize the file natively
        subprocess.run(
            ["qpdf", "--linearize", input_path_to_read, output_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        elapsed = time.time() - start_time
        print(f"\nSuccess! PDF has been linearized in {elapsed:.1f} seconds.")
        print("Your browser can now use HTTP Byte-Range requests to jump to pages instantly.")
        
    except subprocess.CalledProcessError as e:
        print(f"Error processing PDF with qpdf:\n{e.stderr.decode('utf-8', errors='ignore')}")
        if output_path == input_path and 'backup_path' in locals():
            print("Restoring backup...")
            os.rename(backup_path, input_path)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        if output_path == input_path and 'backup_path' in locals():
            os.rename(backup_path, input_path)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python linearize_pdf.py <path_to_pdf>")
        sys.exit(1)
        
    target_pdf = sys.argv[1]
    linearize_pdf(target_pdf)
