#!/usr/bin/env python3
"""
Download DICOM files from The Cancer Imaging Archive (TCIA) REST API.

Uses the NBIA REST API (no authentication required for public collections)
to download DICOM studies across multiple modalities for training data.

Usage:
    python download_tcia.py --output-dir fuzzer/data/training_data/dicom_files --num-studies 200
    python download_tcia.py --collections LIDC-IDRI --num-studies 50
"""

import os
import sys
import argparse
import logging
import zipfile
import tempfile
import time
import io

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("tcia_download.log"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger(__name__)

TCIA_BASE_URL = "https://services.cancerimagingarchive.net/nbia-api/services/v1"

# Public collections with diverse modalities
DEFAULT_COLLECTIONS = [
    "LIDC-IDRI",          # Lung CT
    "TCGA-BRCA",          # Breast
    "Head-Neck-PET-CT",   # Head/Neck PET-CT
    "TCGA-LUAD",          # Lung adenocarcinoma
    "TCGA-GBM",           # Glioblastoma
]

# Target modalities for diversity
TARGET_MODALITIES = ["CT", "MR", "US", "XA", "PT"]


def tcia_get(endpoint, params=None, timeout=60):
    """Make a GET request to the TCIA REST API."""
    url = f"{TCIA_BASE_URL}/{endpoint}"
    headers = {"Accept": "application/json"}
    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.JSONDecodeError:
        return resp.content
    except requests.exceptions.RequestException as e:
        logger.error(f"TCIA API error for {endpoint}: {e}")
        return None


def get_collections():
    """Fetch available public collections."""
    data = tcia_get("getCollectionValues")
    if data is None:
        return []
    return [item.get("Collection", "") for item in data if isinstance(item, dict)]


def get_patient_studies(collection, max_studies=50):
    """Fetch patient/study info for a collection."""
    data = tcia_get("getPatientStudy", params={"Collection": collection})
    if data is None:
        return []
    return data[:max_studies]


def get_series(collection=None, study_uid=None, modality=None):
    """Fetch series for a given study or collection."""
    params = {}
    if collection:
        params["Collection"] = collection
    if study_uid:
        params["StudyInstanceUID"] = study_uid
    if modality:
        params["Modality"] = modality
    data = tcia_get("getSeries", params=params)
    if data is None:
        return []
    return data


def download_series_images(series_uid, output_dir, timeout=120):
    """
    Download all DICOM images for a series as a ZIP and extract.

    Returns the number of DICOM files extracted.
    """
    url = f"{TCIA_BASE_URL}/getImage"
    params = {"SeriesInstanceUID": series_uid}
    try:
        resp = requests.get(url, params=params, timeout=timeout, stream=True)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error(f"Download failed for series {series_uid}: {e}")
        return 0

    # The API returns a ZIP file
    try:
        zip_data = io.BytesIO(resp.content)
        with zipfile.ZipFile(zip_data, 'r') as zf:
            series_dir = os.path.join(output_dir, series_uid[:20])
            os.makedirs(series_dir, exist_ok=True)
            dcm_count = 0
            for name in zf.namelist():
                if name.endswith('/'):
                    continue
                # Extract DICOM files (typically .dcm or no extension)
                target_path = os.path.join(series_dir, os.path.basename(name))
                with zf.open(name) as src, open(target_path, 'wb') as dst:
                    dst.write(src.read())
                dcm_count += 1
            return dcm_count
    except (zipfile.BadZipFile, Exception) as e:
        logger.error(f"Failed to extract series {series_uid}: {e}")
        return 0


def download_studies(collections, output_dir, num_studies=200, max_series_per_study=3):
    """
    Download DICOM studies from TCIA across specified collections.

    Distributes downloads across collections and modalities for diversity.
    """
    os.makedirs(output_dir, exist_ok=True)

    # Check which collections are available
    available = get_collections()
    if not available:
        logger.warning("Could not fetch TCIA collections. Check network connectivity.")
        available = collections  # Try anyway

    valid_collections = [c for c in collections if c in available]
    if not valid_collections:
        logger.warning(f"None of {collections} found in TCIA. Using all requested.")
        valid_collections = collections

    studies_per_collection = max(1, num_studies // len(valid_collections))
    total_files = 0
    total_studies = 0

    for collection in valid_collections:
        if total_studies >= num_studies:
            break

        logger.info(f"Fetching studies from {collection}...")
        studies = get_patient_studies(collection, max_studies=studies_per_collection)

        if not studies:
            logger.warning(f"No studies found for {collection}")
            continue

        for study in studies:
            if total_studies >= num_studies:
                break

            study_uid = study.get("StudyInstanceUID", "")
            if not study_uid:
                continue

            # Get series for this study
            series_list = get_series(study_uid=study_uid)
            if not series_list:
                continue

            # Limit series per study
            series_list = series_list[:max_series_per_study]
            study_files = 0

            for series in series_list:
                series_uid = series.get("SeriesInstanceUID", "")
                if not series_uid:
                    continue

                modality = series.get("Modality", "unknown")
                image_count = series.get("ImageCount", 0)
                logger.info(
                    f"  Downloading series {series_uid[:20]}... "
                    f"(modality={modality}, images={image_count})"
                )

                n = download_series_images(series_uid, output_dir)
                study_files += n
                total_files += n

                # Rate limiting to be respectful to TCIA servers
                time.sleep(0.5)

            if study_files > 0:
                total_studies += 1
                logger.info(
                    f"  Study {total_studies}/{num_studies}: "
                    f"{study_files} files downloaded"
                )

    logger.info(
        f"Download complete: {total_studies} studies, "
        f"{total_files} DICOM files in {output_dir}"
    )
    return total_studies, total_files


def main():
    parser = argparse.ArgumentParser(
        description="Download DICOM files from TCIA for training data generation"
    )
    parser.add_argument(
        "--output-dir", type=str, default="fuzzer/data/training_data/dicom_files",
        help="Output directory for downloaded DICOM files",
    )
    parser.add_argument(
        "--num-studies", type=int, default=200,
        help="Number of studies to download (default: 200)",
    )
    parser.add_argument(
        "--collections", type=str, nargs="+", default=None,
        help="TCIA collection names to download from",
    )
    parser.add_argument(
        "--max-series-per-study", type=int, default=3,
        help="Max series to download per study (default: 3)",
    )
    parser.add_argument(
        "--list-collections", action="store_true",
        help="List available TCIA collections and exit",
    )

    args = parser.parse_args()

    if args.list_collections:
        print("Fetching available TCIA collections...")
        collections = get_collections()
        if collections:
            for c in sorted(collections):
                print(f"  {c}")
            print(f"\nTotal: {len(collections)} collections")
        else:
            print("Could not fetch collections. Check network connectivity.")
        return

    collections = args.collections or DEFAULT_COLLECTIONS

    print("\n" + "=" * 70)
    print("TCIA DICOM DOWNLOADER")
    print("=" * 70)
    print(f"Collections: {', '.join(collections)}")
    print(f"Target studies: {args.num_studies}")
    print(f"Output: {args.output_dir}")
    print("=" * 70 + "\n")

    n_studies, n_files = download_studies(
        collections, args.output_dir,
        num_studies=args.num_studies,
        max_series_per_study=args.max_series_per_study,
    )

    print(f"\nDone: {n_studies} studies, {n_files} DICOM files")
    print(f"Output: {args.output_dir}\n")


if __name__ == "__main__":
    main()
