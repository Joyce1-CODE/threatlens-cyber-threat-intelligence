import csv
import io
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.ioc_validator import validate_and_normalize_ioc, IOCValidationError
from app.services.aggregator import ThreatAggregator
from app.services.history_service import HistoryService
from app.services.rate_limiter import ProviderRateLimiter

MAX_BATCH_SIZE = 50
MAX_CSV_BYTES = 2 * 1024 * 1024 # 2 Megabytes

INDICATOR_COLUMN_CANDIDATES = [
    "indicator", "ioc", "iocs", "ip", "ip_address", "domain", "url",
    "hash", "file_hash", "md5", "sha256", "sha1", "target", "host", "address"
]

class BulkServiceError(Exception):
    pass

class BulkService:
    @staticmethod
    def preview_csv_content(content_bytes: bytes, filename: str = "upload.csv") -> Dict[str, Any]:
        """
        Parses and validates CSV content for pre-flight review.
        Enforces 2MB file limit and max 50 unique indicators.
        """
        if len(content_bytes) > MAX_CSV_BYTES:
            raise BulkServiceError(f"File size ({len(content_bytes) / 1024:.1f} KB) exceeds maximum 2 MB limit.")

        if not content_bytes.strip():
            raise BulkServiceError("Uploaded CSV file is empty.")

        # Decode content with UTF-8 or Latin-1 fallback
        try:
            text = content_bytes.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = content_bytes.decode("latin-1")
            except Exception as e:
                raise BulkServiceError(f"Unable to decode CSV text: {str(e)}")

        # Detect dialect & delimiter
        sample = text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            sniffed_has_header = csv.Sniffer().has_header(sample)
        except Exception:
            dialect = csv.excel
            sniffed_has_header = True

        reader = csv.reader(io.StringIO(text), dialect=dialect)
        rows = [r for r in reader if r and any(cell.strip() for cell in r)]

        if not rows:
            raise BulkServiceError("No non-empty rows found in CSV file.")

        # Robust check if first row contains indicator-like or standard CSV column names
        first_row_cleaned = [c.strip().lower().replace(" ", "_").replace("-", "_") for c in rows[0]]
        known_header_words = set(INDICATOR_COLUMN_CANDIDATES + ["source", "notes", "description", "label", "category", "date", "timestamp"])
        has_known_vocab = any(c in known_header_words for c in first_row_cleaned)

        has_header = (has_known_vocab or sniffed_has_header) and len(rows) > 1

        headers: List[str] = []
        data_rows: List[List[str]] = []

        if has_header:
            headers = [h.strip() for h in rows[0]]
            data_rows = rows[1:]
        else:
            headers = [f"Column_{i+1}" for i in range(len(rows[0]))]
            data_rows = rows

        # Identify candidate indicator column
        detected_col_idx = 0
        detected_col_name = headers[0]
        for idx, h in enumerate(headers):
            clean_h = h.lower().replace(" ", "_").replace("-", "_")
            if clean_h in INDICATOR_COLUMN_CANDIDATES:
                detected_col_idx = idx
                detected_col_name = h
                break

        # Validate rows and check duplicates
        seen_normalized = set()
        items: List[Dict[str, Any]] = []
        valid_count = 0
        invalid_count = 0
        duplicate_count = 0
        truncated_count = 0

        for row_idx, row in enumerate(data_rows, start=2 if has_header else 1):
            if detected_col_idx < len(row):
                raw_val = row[detected_col_idx].strip()
            else:
                raw_val = ""

            if not raw_val:
                continue

            try:
                normalized, ioc_type = validate_and_normalize_ioc(raw_val)
                is_valid = True
                error_msg = None
            except IOCValidationError as err:
                normalized = raw_val
                ioc_type = "unknown"
                is_valid = False
                error_msg = str(err)

            is_duplicate = False
            if is_valid:
                if normalized in seen_normalized:
                    is_duplicate = True
                    duplicate_count += 1
                else:
                    seen_normalized.add(normalized)
                    if len(seen_normalized) <= MAX_BATCH_SIZE:
                        valid_count += 1
                    else:
                        truncated_count += 1
            else:
                invalid_count += 1

            is_exceeding_limit = len(seen_normalized) > MAX_BATCH_SIZE and not is_duplicate

            items.append({
                "row_number": row_idx,
                "original": raw_val,
                "normalized": normalized,
                "type": ioc_type,
                "is_valid": is_valid,
                "is_duplicate": is_duplicate,
                "is_exceeded": is_exceeding_limit,
                "error": error_msg,
            })

        return {
            "filename": filename,
            "total_rows": len(data_rows),
            "available_columns": headers,
            "detected_column": detected_col_name,
            "detected_column_index": detected_col_idx,
            "valid_count": min(valid_count, MAX_BATCH_SIZE),
            "invalid_count": invalid_count,
            "duplicate_count": duplicate_count,
            "truncated_count": truncated_count,
            "max_batch_size": MAX_BATCH_SIZE,
            "items": items,
        }

    @staticmethod
    async def process_batch_triage(
        items: List[Dict[str, str]],
        db: Session,
        concurrency: int = 4,
        rate_limiter: Optional[ProviderRateLimiter] = None
    ) -> Dict[str, Any]:
        """
        Executes bounded concurrent investigation for a batch of up to 50 indicators.
        Persists each completed investigation to SQLite with rate-limit protection.
        """
        unique_targets: List[Tuple[str, str]] = []
        seen = set()

        for it in items:
            raw = it.get("indicator", "").strip()
            explicit_type = it.get("indicator_type", "auto")
            if not raw:
                continue
            if raw not in seen:
                seen.add(raw)
                unique_targets.append((raw, explicit_type))
            if len(unique_targets) >= MAX_BATCH_SIZE:
                break

        aggregator = ThreatAggregator()
        semaphore = asyncio.Semaphore(concurrency)

        # Initialize rate limiter with provider pacing if not supplied
        if rate_limiter is None:
            # Pacing: 15s between VT requests if VT key configured; 0.5s for OTX; 0s if missing keys
            vt_pacing = 15.0 if aggregator.vt.is_configured else 0.0
            otx_pacing = 0.5 if aggregator.otx.is_configured else 0.0
            rate_limiter = ProviderRateLimiter(
                vt_interval_seconds=vt_pacing,
                otx_interval_seconds=otx_pacing
            )

        async def _triage_single(raw_indicator: str, req_type: str) -> Dict[str, Any]:
            async with semaphore:
                try:
                    norm_ind, detected_t = validate_and_normalize_ioc(raw_indicator, req_type)
                except IOCValidationError as err:
                    return {
                        "id": None,
                        "indicator": raw_indicator,
                        "normalized_indicator": raw_indicator,
                        "indicator_type": "invalid",
                        "risk_score": 0,
                        "severity": "Unknown",
                        "confidence": "None",
                        "data_coverage": "Validation Failed",
                        "vt_status": "skipped",
                        "otx_status": "skipped",
                        "vt_detections": 0,
                        "vt_total_engines": 0,
                        "otx_pulse_count": 0,
                        "verdict_summary": f"Validation Error: {str(err)}",
                        "status": "invalid",
                        "error": str(err),
                        "created_at": None,
                    }

                agg_result = await aggregator.investigate(
                    norm_ind,
                    detected_t,
                    rate_limiter=rate_limiter
                )

                record = HistoryService.create_investigation(
                    db=db,
                    indicator=raw_indicator,
                    normalized_indicator=norm_ind,
                    indicator_type=detected_t,
                    aggregated_data=agg_result
                )

                return {
                    "id": record.id,
                    "indicator": record.indicator,
                    "normalized_indicator": record.normalized_indicator,
                    "indicator_type": record.indicator_type,
                    "risk_score": record.risk_score,
                    "severity": record.severity,
                    "confidence": record.confidence,
                    "data_coverage": record.data_coverage,
                    "vt_status": record.vt_status,
                    "otx_status": record.otx_status,
                    "vt_detections": record.vt_detections,
                    "vt_total_engines": record.vt_total_engines,
                    "otx_pulse_count": record.otx_pulse_count,
                    "verdict_summary": record.verdict_summary,
                    "status": "completed",
                    "error": None,
                    "created_at": record.created_at.isoformat() if record.created_at else None,
                }

        tasks = [_triage_single(ind, t) for ind, t in unique_targets]
        results = await asyncio.gather(*tasks)

        completed_count = sum(1 for r in results if r["status"] == "completed")
        invalid_count = sum(1 for r in results if r["status"] == "invalid")
        high_critical = sum(1 for r in results if r["severity"] in ("High", "Critical"))
        clean_count = sum(1 for r in results if r["severity"] == "Low" and r["status"] == "completed")
        rate_limited_count = sum(
            1 for r in results
            if r.get("vt_status") == "rate_limited" or r.get("otx_status") == "rate_limited"
        )

        return {
            "total_submitted": len(unique_targets),
            "completed": completed_count,
            "invalid": invalid_count,
            "high_critical_count": high_critical,
            "clean_count": clean_count,
            "rate_limited_count": rate_limited_count,
            "results": results,
        }

    @staticmethod
    def generate_results_csv(results: List[Dict[str, Any]]) -> str:
        """
        Exports triage results to RFC-4180 compliant CSV string.
        """
        output = io.StringIO()
        fieldnames = [
            "Original Indicator",
            "Normalized Indicator",
            "Indicator Type",
            "Risk Score",
            "Severity",
            "Confidence",
            "Data Coverage",
            "VirusTotal Status",
            "VirusTotal Detections",
            "AlienVault OTX Status",
            "AlienVault OTX Pulses",
            "Status",
            "Verdict Summary",
            "Investigation ID",
            "Timestamp",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for r in results:
            writer.writerow({
                "Original Indicator": r.get("indicator", ""),
                "Normalized Indicator": r.get("normalized_indicator", ""),
                "Indicator Type": r.get("indicator_type", ""),
                "Risk Score": r.get("risk_score", 0),
                "Severity": r.get("severity", ""),
                "Confidence": r.get("confidence", ""),
                "Data Coverage": r.get("data_coverage", ""),
                "VirusTotal Status": r.get("vt_status", ""),
                "VirusTotal Detections": r.get("vt_detections", 0),
                "AlienVault OTX Status": r.get("otx_status", ""),
                "AlienVault OTX Pulses": r.get("otx_pulse_count", 0),
                "Status": r.get("status", ""),
                "Verdict Summary": r.get("verdict_summary", ""),
                "Investigation ID": r.get("id", ""),
                "Timestamp": r.get("created_at", ""),
            })

        return output.getvalue()
