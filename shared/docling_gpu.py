"""Docling converter pinned to CUDA for layout, OCR, and tables."""

from __future__ import annotations

from functools import lru_cache

import config


@lru_cache(maxsize=1)
def get_docling_converter():
    from docling.datamodel.accelerator_options import AcceleratorOptions
    from docling.datamodel.base_models import InputFormat
    from docling.datamodel.pipeline_options import PdfPipelineOptions, RapidOcrOptions
    from docling.document_converter import DocumentConverter, PdfFormatOption

    device = "cuda:0"
    pipeline = PdfPipelineOptions(
        do_ocr=True,
        do_table_structure=True,
        ocr_batch_size=config.DOCLING_OCR_BATCH_SIZE,
        layout_batch_size=config.DOCLING_LAYOUT_BATCH_SIZE,
        table_batch_size=config.DOCLING_TABLE_BATCH_SIZE,
        accelerator_options=AcceleratorOptions(
            device=device,
            num_threads=max(config.DOCLING_NUM_THREADS, 8),
        ),
        ocr_options=RapidOcrOptions(backend="torch", lang=["english"]),
    )
    print(
        f"[docling] CUDA converter: device={device} "
        f"layout_batch={pipeline.layout_batch_size} "
        f"ocr_batch={pipeline.ocr_batch_size} ocr_backend=torch"
    )
    return DocumentConverter(
        format_options={
            InputFormat.PDF: PdfFormatOption(pipeline_options=pipeline),
        }
    )
