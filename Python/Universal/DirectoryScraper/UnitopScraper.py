### Scraper_Unifile_Fetcher
### Created by KrazierOne
### V1.0 (Interactive, clean flags output)

# =================================
# DEFAULT VARIABLES (can be overridden)
# =================================
ORGANIZATION = ""  
MIN_FILES = 3
MAX_FILES = 5
RECURSIVE = True
VALID_KEYWORDS = []  
FOLDER = r"C:\File\Path"
CONTENT_SCAN_BYTES = 4096  
OUTPUT_LOG = "scraper_report.txt"
FAILED_LOG = "failed_log.txt"

# =================================
# DEPENDENCIES
# =================================
import importlib, subprocess, sys

def ensure_package(pkg, import_name=None):
    try:
        return importlib.import_module(import_name or pkg)
    except ImportError:
        print(f"[!] {pkg} not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return importlib.import_module(import_name or pkg)

pypdf = ensure_package("pypdf")  
PIL = ensure_package("pillow", "PIL")
ezdxf = ensure_package("ezdxf")

import os
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
import re
from pypdf import PdfReader
from PIL import Image
from PIL.ExifTags import TAGS
import ezdxf

# =================================
# METADATA FUNCTIONS
# =================================
def extract_pdf_metadata(path):
    try:
        reader = PdfReader(path)
        info = reader.metadata
        date_str = info.get("/CreationDate", None)
        if date_str:
            m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})", date_str)
            if m:
                dt = datetime(*map(int, m.groups()))
                return dt.strftime("%Y-%m-%d %H:%M:%S")
        return None
    except:
        return None

def extract_office_metadata(path):
    try:
        with zipfile.ZipFile(path, "r") as z:
            if "docProps/core.xml" in z.namelist():
                xml_content = z.read("docProps/core.xml")
                root = ET.fromstring(xml_content)
                for elem in root:
                    if elem.tag.endswith("created"):
                        return elem.text
        return None
    except:
        return None

def extract_image_metadata(path):
    try:
        img = Image.open(path)
        exif_data = img._getexif()
        if not exif_data:
            return None
        for tag, value in exif_data.items():
            tag_name = TAGS.get(tag, tag)
            if tag_name == "DateTimeOriginal":
                return value
        return None
    except:
        return None

def extract_cad_metadata(path):
    try:
        doc = ezdxf.readfile(path)
        created = doc.header.get("$TDCREATE", None)
        return created
    except:
        return None

def extract_metadata(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return extract_pdf_metadata(path)
    elif ext in [".docx", ".xlsx", ".pptx", ".odt", ".ods", ".ppt"]:
        return extract_office_metadata(path)
    elif ext in [".jpg", ".jpeg", ".png", ".tiff"]:
        return extract_image_metadata(path)
    elif ext in [".dwg", ".dxf", ".cad"]:
        return extract_cad_metadata(path)
    else:
        return None

# =================================
# FILE SCANNING
# =================================
def scan_file(path):
    try:
        cdate = extract_metadata(path)
        identifiers = []

        try:
            with open(path, "rb") as f:
                chunk = f.read(CONTENT_SCAN_BYTES).decode("utf-8", errors="ignore").lower()
                if ORGANIZATION and ORGANIZATION.lower() in chunk:
                    identifiers.append("ORG_MATCH")
                for keyword in VALID_KEYWORDS:
                    if keyword.lower() in chunk:
                        identifiers.append(f"KEYWORD:{keyword}")
        except Exception:
            identifiers.append("CONTENT_UNREADABLE")

        # Determine grade
        if "CONTENT_UNREADABLE" in identifiers:
            grade = "||Excluded||"
        elif identifiers != ["None"] and identifiers != []:
            grade = "||Included||"
        else:
            grade = "||Probable||"

        return {
            "file": os.path.basename(path),
            "ext": os.path.splitext(path)[1][1:],
            "cDate": cdate,
            "identifiers": identifiers or ["None"],
            "grade": grade
        }
    except Exception as e:
        log_failure(path, str(e))
        return None

# =================================
# LOGGING
# =================================
def log_results(results, title, min_files_list=None):
    with open(OUTPUT_LOG, "a", encoding="utf-8") as log:
        log.write(f"\n>>> {title} <<<\n")
        for idx, r in enumerate(results, start=1):
            min_flag = "||Min||" if min_files_list and r in min_files_list else ""
            log.write(f"{idx}. {r['grade']} {min_flag} {r['file']} ({r['ext']}) | cDate: {r['cDate']}\n")

def log_failure(path, error):
    with open(FAILED_LOG, "a", encoding="utf-8") as flog:
        flog.write(f"{path}: {error}\n")

# =================================
# MAIN PROCESS
# =================================
def run_scraper():
    global VALID_KEYWORDS, FOLDER, MIN_FILES, MAX_FILES, ORGANIZATION, RECURSIVE

    # Clear logs
    open(OUTPUT_LOG, "w", encoding="utf-8").close()
    open(FAILED_LOG, "w", encoding="utf-8").close()

    # Edit parameters
    edit_params = input("Do you want to edit default parameters? (y/n): ").strip().lower()
    if edit_params == "y":
        folder_input = input(f"Folder path to scan [{FOLDER}]: ").strip()
        if folder_input: FOLDER = folder_input

        org_input = input(f"Organization name to match [{ORGANIZATION}]: ").strip()
        if org_input: ORGANIZATION = org_input

        min_files_input = input(f"Minimum files to return [{MIN_FILES}]: ").strip()
        if min_files_input.isdigit(): MIN_FILES = int(min_files_input)

        max_files_input = input(f"Maximum files to return [{MAX_FILES}]: ").strip()
        if max_files_input.isdigit(): MAX_FILES = int(max_files_input)

        recursive_input = input(f"Scan subdirectories? (y/n) [{'y' if RECURSIVE else 'n'}]: ").strip().lower()
        if recursive_input in ["y", "n"]: RECURSIVE = recursive_input == "y"

    # Custom keywords
    keywords_input = input("Enter VALID keywords (comma-separated, leave blank to keep none): ").strip()
    if keywords_input:
        VALID_KEYWORDS = [k.strip() for k in keywords_input.split(",")]

    # Scan files
    all_files = []
    for root, dirs, files in os.walk(FOLDER):
        for file in files:
            filepath = os.path.join(root, file)
            result = scan_file(filepath)
            if result:
                all_files.append(result)
        if not RECURSIVE:
            break

    # Sort MAX list by grade: Included > Probable > Excluded
    grade_order = {"||Included||": 0, "||Probable||": 1, "||Excluded||": 2}
    sorted_files = sorted(all_files, key=lambda x: grade_order.get(x["grade"], 3))

    min_list = sorted_files[:MIN_FILES] if MIN_FILES <= len(sorted_files) else sorted_files
    max_list = sorted_files[:MAX_FILES]

    # Log MIN first
    log_results(min_list, "MIN FILES LIST (most likely files)")
    log_results(max_list, "MAX FILES LIST (probable files)", min_files_list=min_list)

if __name__ == "__main__":
    run_scraper()
    print(f"Scan complete. Results in {OUTPUT_LOG}, failures in {FAILED_LOG}")
