from __future__ import annotations

from pathlib import Path

from fastapi import UploadFile


TEXT_FILE_SUFFIXES = {".txt", ".md", ".csv", ".json", ".log"}
MAX_TEXT_BYTES = 250_000


async def read_uploads(files: list[UploadFile]) -> tuple[str, list[dict[str, str]]]:
    extracted_chunks: list[str] = []
    uploaded_files: list[dict[str, str]] = []

    for file in files:
        if not file.filename:
            continue

        content_type = file.content_type or ""
        filename = file.filename
        suffix = Path(filename).suffix.lower()
        file_info = {
            "name": filename,
            "content_type": content_type,
            "note": "Upload received. Paste screenshot/PDF text when OCR is needed.",
        }

        if content_type.startswith("text/") or suffix in TEXT_FILE_SUFFIXES:
            raw_content = await file.read(MAX_TEXT_BYTES + 1)
            trimmed_content = raw_content[:MAX_TEXT_BYTES]
            text = decode_text_upload(trimmed_content)
            if text.strip():
                extracted_chunks.append(f"\n\n--- Uploaded file: {filename} ---\n{text.strip()}")
                file_info["note"] = "Text extracted and included in this analysis."
            else:
                file_info["note"] = "Text file was uploaded, but no readable text was found."

        uploaded_files.append(file_info)

    return "\n".join(extracted_chunks).strip(), uploaded_files


def decode_text_upload(content: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return ""
