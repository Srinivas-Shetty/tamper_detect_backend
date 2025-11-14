


# from fastapi import FastAPI, File, UploadFile
# from fastapi.responses import JSONResponse
# from PIL import Image, ImageChops
# import io, hashlib, magic, exifread, cv2, numpy as np
# from PyPDF2 import PdfReader
# from pdf2image import convert_from_bytes
# import pytesseract

# # ✅ Set tesseract path if not in PATH
# # pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# app = FastAPI(title="Document Tampering Detection API", version="4.0")


# # -----------------------------------------------------------
# # 🧠 Utility Helpers
# # -----------------------------------------------------------
# def sha256_of_bytes(b: bytes) -> str:
#     h = hashlib.sha256()
#     h.update(b)
#     return h.hexdigest()


# def mime_type_of_bytes(b: bytes) -> str:
#     try:
#         return magic.from_buffer(b, mime=True)
#     except Exception:
#         return "application/octet-stream"


# # -----------------------------------------------------------
# # 📄 PDF Forensics
# # -----------------------------------------------------------
# def analyze_pdf_bytes(b: bytes):
#     out = {"type": "pdf", "metadata": {}, "suspicious": [], "source_category": "", "risk_level": "low"}
#     try:
#         reader = PdfReader(io.BytesIO(b))
#         meta = {k[1:]: v for k, v in (reader.metadata or {}).items()}
#         out["metadata"] = meta

#         creator = meta.get("Creator", "") or meta.get("Producer", "")
#         creation = meta.get("CreationDate", "")
#         modified = meta.get("ModDate", "")

#         # --- Classification sets ---
#         manual_tools = ["Word", "Photoshop", "Canva", "Figma", "PowerPoint", "LibreOffice", "WPS", "Illustrator", "Docx"]
#         # corporate_generators = ["itext", "wkhtmltopdf", "tcpdf", "jspdf", "adobe pdf library"]
#         corporate_generators = [
#     "itext", "wkhtmltopdf", "tcpdf", "jspdf", "adobe pdf library",
#     "jasperreports", "birt", "crystal reports", "pentaho", "oracle reports"
# ]
#         ai_generators = ["reportlab", "weasyprint", "pydf", "pdfkit", "chromium pdf", "playwright pdf"]

#         # --- Rule 1: Detect manual creation ---
#         if any(tool.lower() in creator.lower() for tool in manual_tools):
#             out["suspicious"].append(f"Created using {creator} → user-generated document")
#             out["source_category"] = "manual"
#             out["risk_level"] = "high"

#         # --- Rule 2: Detect AI-generated PDFs ---
#         elif any(ai.lower() in creator.lower() for ai in ai_generators):
#             out["suspicious"].append(f"Generated using {creator} → likely AI or automated PDF")
#             out["source_category"] = "ai"
#             out["risk_level"] = "medium"

#         # --- Rule 3: Corporate PDF Generators ---
#         elif any(safe in creator.lower() for safe in corporate_generators):
#             out["source_category"] = "corporate"
#             out["risk_level"] = "low"

#         else:
#             out["source_category"] = "unknown"
#             out["risk_level"] = "medium"
#             out["suspicious"].append(f"Unknown or unlisted PDF producer: {creator}")

#         # --- Rule 4: Modified after creation ---
#         if creation and modified and creation != modified:
#             out["suspicious"].append("Modified after original creation")
#             out["risk_level"] = "high"

#         # --- Rule 5: Missing signature (except corporate) ---
#         if out["source_category"] not in ["corporate"]:
#             if not any("Signature" in k for k in meta.keys()):
#                 out["suspicious"].append("No digital signature metadata found")

#         # --- Rule 6: No embedded fonts (for AI/manual/unknown) ---
#         if out["source_category"] in ["ai", "manual", "unknown"]:
#             if "/Font" not in str(reader.trailer):
#                 out["suspicious"].append("No embedded fonts → possibly scanned or AI-generated image PDF")

#     except Exception as e:
#         out["error"] = str(e)
#         out["source_category"] = "error"
#         out["risk_level"] = "high"

#     return out


# def extract_text_from_pdf_bytes(b: bytes) -> str:
#     try:
#         pages = convert_from_bytes(b)
#         text = [pytesseract.image_to_string(p) for p in pages]
#         return "\n".join(text)
#     except Exception:
#         return ""


# # -----------------------------------------------------------
# # 🖼️ Image Forensics
# # -----------------------------------------------------------
# def extract_exif_from_bytes(b: bytes):
#     try:
#         return {k: str(v) for k, v in exifread.process_file(io.BytesIO(b), details=False).items()}
#     except:
#         return {}


# def ela_score(pil_img):
#     buf = io.BytesIO()
#     pil_img.save(buf, "JPEG", quality=90)
#     buf.seek(0)
#     recompressed = Image.open(buf)
#     ela = ImageChops.difference(pil_img, recompressed)
#     ela = Image.eval(ela, lambda x: min(255, x * 12))
#     return float(np.asarray(ela).mean())


# def copy_move_score(pil_img):
#     img = np.array(pil_img.convert("RGB"))
#     gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
#     orb = cv2.ORB_create(1500)
#     kp, des = orb.detectAndCompute(gray, None)
#     if des is None:
#         return 0.0
#     bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
#     matches = bf.knnMatch(des, des, k=2)
#     good = []
#     for m, n in matches:
#         if m.distance < 0.75 * n.distance and m.queryIdx != m.trainIdx:
#             p1, p2 = kp[m.queryIdx].pt, kp[m.trainIdx].pt
#             if np.linalg.norm(np.array(p1) - np.array(p2)) > 20:
#                 good.append(m)
#     return min(1.0, len(good) / 100)


# def image_forensics_from_bytes(b: bytes):
#     pil_img = Image.open(io.BytesIO(b)).convert("RGB")
#     gray = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2GRAY)
#     ela = ela_score(pil_img)
#     cm = copy_move_score(pil_img)
#     blur = cv2.Laplacian(gray, cv2.CV_64F).var()
#     exif = extract_exif_from_bytes(b)

#     susp = []
#     if not exif:
#         susp.append("Missing EXIF")
#     if ela > 20:
#         susp.append("High ELA → edited")
#     if cm > 0.5:
#         susp.append("Copy-move pattern found")
#     if blur < 15:
#         susp.append("Unnaturally low sharpness")

#     risk = "low"
#     if ela > 40 or cm > 0.6:
#         risk = "high"
#     elif ela > 20 or cm > 0.3:
#         risk = "medium"

#     return {
#         "type": "image",
#         "ela_score": ela,
#         "copy_move_score": cm,
#         "blur": blur,
#         "exif": exif,
#         "suspicious": susp,
#         "source_category": "image",
#         "risk_level": risk,
#     }


# # -----------------------------------------------------------
# # 🔠 OCR Helpers
# # -----------------------------------------------------------
# def extract_text_from_image_bytes(b: bytes) -> str:
#     try:
#         return pytesseract.image_to_string(Image.open(io.BytesIO(b)))
#     except:
#         return ""


# # -----------------------------------------------------------
# # 🧮 Scoring + Risk Mapping
# # -----------------------------------------------------------
# def aggregate(parts):
#     reasons = []
#     score = 0.0
#     overall_risk = "low"
#     category = "unknown"

#     for p in parts:
#         reasons.extend(p.get("suspicious", []))
#         category = p.get("source_category", category)

#         if p.get("type") == "pdf":
#             score += len(p.get("suspicious", [])) * 15

#         if p.get("type") == "image":
#             score += p.get("ela_score", 0) / 5
#             score += p.get("copy_move_score", 0) * 40
#             if p.get("suspicious"):
#                 score += len(p.get("suspicious")) * 10

#         # Risk aggregation
#         if p.get("risk_level") == "high":
#             overall_risk = "high"
#         elif p.get("risk_level") == "medium" and overall_risk != "high":
#             overall_risk = "medium"

#     score = round(min(score, 100), 2)

#     # Derive risk from score
#     if score >= 70:
#         overall_risk = "high"
#     elif score >= 40:
#         overall_risk = "medium"

#     return {
#         "tamper_score": score,
#         "source_category": category,
#         "risk_level": overall_risk,
#         "reasons": reasons,
#     }


# # -----------------------------------------------------------
# # 🚀 API Endpoint
# # -----------------------------------------------------------
# @app.post("/check-document")
# async def check_document(file: UploadFile = File(...)):
#     content = await file.read()
#     fname = file.filename
#     mime = mime_type_of_bytes(content)
#     sha = sha256_of_bytes(content)
#     parts = []

#     if "pdf" in mime or fname.lower().endswith(".pdf"):
#         pdf = analyze_pdf_bytes(content)
#         pdf["ocr_snippet"] = extract_text_from_pdf_bytes(content)[:300]
#         parts.append(pdf)
#     elif mime.startswith("image/"):
#         img = image_forensics_from_bytes(content)
#         img["ocr_snippet"] = extract_text_from_image_bytes(content)[:300]
#         parts.append(img)
#     else:
#         return JSONResponse({"error": f"Unsupported type {mime}"})

#     return {
#         "file_info": {"filename": fname, "mime": mime, "sha256": sha},
#         "parts": parts,
#         "aggregate": aggregate(parts),
#     }


from fastapi import FastAPI, File, UploadFile
from fastapi.responses import JSONResponse
from PIL import Image, ImageChops
import io, hashlib, magic, exifread, cv2, numpy as np
from PyPDF2 import PdfReader
from pdf2image import convert_from_bytes
import pytesseract
import logging
from typing import Optional

# Optional imports (best-effort)
try:
    # pyhanko provides real PDF signature verification
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext  # may be optional in some installs
    PYHANKO_AVAILABLE = True
except Exception:
    PYHANKO_AVAILABLE = False

try:
    # for semantic similarity (optional heavy dependency)
    from sentence_transformers import SentenceTransformer, util as st_util
    S2_AVAILABLE = True
    # small default model name — will download on first run
    S2_MODEL_NAME = "all-MiniLM-L6-v2"
    _s2_model = None
except Exception:
    S2_AVAILABLE = False
    _s2_model = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tamper_api")

# If Tesseract not in PATH, uncomment and set path:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = FastAPI(title="Document Tampering Detection API", version="4.1")


# -----------------------
# Utility helpers
# -----------------------
def sha256_of_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def mime_type_of_bytes(b: bytes) -> str:
    try:
        return magic.from_buffer(b, mime=True)
    except Exception:
        return "application/octet-stream"


# -----------------------
# PDF signature helpers (Level 2)
# -----------------------
def detect_embedded_signature_bytes(b: bytes) -> bool:
    """
    Quick check: look for /Sig or /ByteRange objects in the raw PDF bytes.
    This is fast and catches most embedded signatures.
    """
    try:
        small = b[:20000].lower() + b[-20000:].lower()
        if b"/sig" in small or b"/byterange" in small or b"/signature" in small:
            return True
        # PyPDF2 can list /AcroForm fields and you can search, but raw bytes is fastest
        return False
    except Exception:
        return False


def verify_pdf_signature_with_pyhanko_bytes(b: bytes) -> Optional[dict]:
    """
    Attempt real cryptographic validation via pyhanko if available.
    Returns a dict with verification summary or None if pyhanko not available.
    This is best-effort — pyhanko needs CA trust setup to fully mark a chain trusted.
    """
    if not PYHANKO_AVAILABLE:
        return None

    try:
        # pyhanko.sign.validation.validate_pdf_signature wants a file-like object and signature index or name
        # We will call it in a simple best-effort way. pyhanko API is extensive; real integration may require extra configuration.
        from io import BytesIO
        bio = BytesIO(b)

        # Attempt a generic validation — this API can vary with pyhanko versions.
        # We'll call validate_pdf_signature, but wrap in try/except to guard version differences.
        result = {}
        try:
            # This attempts to validate all signatures and return a summary.
            v_result = validate_pdf_signature(bio)
            # v_result may be complex; we'll summarize
            result["pyhanko_summary"] = str(v_result)
            # mark that signature found and pyhanko ran
            result["verified_by_pyhanko"] = True
        except Exception as e:
            result["pyhanko_error"] = str(e)
            result["verified_by_pyhanko"] = False

        return result
    except Exception as e:
        logger.exception("pyhanko verification failed")
        return {"error": str(e)}


# -----------------------
# Content / NLP helpers (Level 3)
# -----------------------
def get_s2_model():
    global _s2_model
    if not S2_AVAILABLE:
        return None
    if _s2_model is None:
        try:
            _s2_model = SentenceTransformer(S2_MODEL_NAME)
        except Exception as e:
            logger.exception("Failed to load sentence-transformers model")
            _s2_model = None
    return _s2_model


def semantic_similarity_score(text_a: str, text_b: str) -> Optional[float]:
    """
    Returns cosine similarity 0..1 using sentence-transformers if available,
    otherwise returns None.
    """
    model = get_s2_model()
    if not model:
        return None
    try:
        # short-circuit for empty text
        if not text_a or not text_b:
            return 0.0
        emb1 = model.encode(text_a, convert_to_tensor=True)
        emb2 = model.encode(text_b, convert_to_tensor=True)
        sim = float(st_util.cos_sim(emb1, emb2).cpu().numpy())
        return sim
    except Exception as e:
        logger.exception("semantic similarity failed")
        return None


def content_keyword_checks(ocr_text: str, meta: dict) -> list:
    """
    Lightweight keyword/heuristic rules comparing OCR text vs metadata.
    Returns list of suspicious reasons.
    """
    reasons = []
    ocr_lower = (ocr_text or "").lower()

    # 1) Company name mismatch: if metadata contains known company token but text doesn't
    # e.g., meta['Producer'] or meta['Title'] or file name may contain "icici" etc.
    # We'll check Producer, Creator, Title, Author
    key_fields = []
    for k in ("Producer", "Creator", "Title", "Author", "Subject"):
        v = meta.get(k)
        if v:
            key_fields.append(str(v).lower())

    # Extract tokens from metadata
    meta_tokens = set()
    for v in key_fields:
        for tok in v.replace("/", " ").replace("-", " ").split():
            if len(tok) > 2:
                meta_tokens.add(tok.strip())

    # If meta has a clear organization token (bank, ltd, inc), ensure OCR includes it
    org_tokens = [t for t in meta_tokens if any(k in t for k in ["bank", "ltd", "inc", "corp", "limited", "company"])]
    if org_tokens:
        found_any = any(tok in ocr_lower for tok in org_tokens)
        if not found_any:
            reasons.append(f"Metadata mentions organization tokens {org_tokens} but OCR text does not contain them")

    # 2) Type mismatch: file suggests 'statement' but OCR contains 'Offer' or 'Salary' or vice versa
    # quick heuristic keywords:
    statement_words = ["statement", "transaction", "balance", "ifsc", "account", "bank"]
    offer_words = ["offer", "salary", "designation", "ctc", "joining", "offer letter"]
    ocr_has_statement = any(w in ocr_lower for w in statement_words)
    ocr_has_offer = any(w in ocr_lower for w in offer_words)

    # If both present that's ok; if Producer suggests corporate but OCR is clearly an offer -> suspicious
    if any("statement" in f for f in meta_tokens) and ocr_has_offer:
        reasons.append("Metadata suggests a statement but OCR text contains offer-letter phrases")

    if any("offer" in f for f in meta_tokens) and ocr_has_statement:
        reasons.append("Metadata suggests an offer but OCR text contains bank-statement phrases")

    # 3) Short or empty OCR but pdf contains many pages -> suspicious (maybe image-only PDF)
    if not ocr_lower.strip():
        reasons.append("OCR returned empty text — PDF may be image-only or low-quality scan")

    return reasons


# -----------------------
# PDF Forensics (updated)
# -----------------------
def analyze_pdf_bytes(b: bytes):
    out = {"type": "pdf", "metadata": {}, "suspicious": [], "source_category": "", "risk_level": "low", "signature": {}}
    try:
        reader = PdfReader(io.BytesIO(b))
        meta = {k[1:]: v for k, v in (reader.metadata or {}).items()}
        out["metadata"] = meta

        creator = (meta.get("Creator", "") or meta.get("Producer", "") or "").strip()
        creation = meta.get("CreationDate", "")
        modified = meta.get("ModDate", "")

        # Classification sets (we will load dynamic config elsewhere in future)
        manual_tools = ["word", "photoshop", "canva", "figma", "powerpoint", "libreoffice", "wps", "illustrator", "docx"]
        corporate_generators = [
            "itext", "wkhtmltopdf", "tcpdf", "jspdf", "adobe pdf library",
            "jasperreports", "birt", "crystal reports", "pentaho", "oracle reports"
        ]
        ai_generators = ["reportlab", "weasyprint", "pydf", "pdfkit", "chromium pdf", "playwright pdf"]

        creator_low = creator.lower()

        # source category
        if any(tool in creator_low for tool in manual_tools):
            out["suspicious"].append(f"Created using {creator} → user-generated document")
            out["source_category"] = "manual"
            out["risk_level"] = "high"
        elif any(ai in creator_low for ai in ai_generators):
            out["suspicious"].append(f"Generated using {creator} → likely AI or automated PDF")
            out["source_category"] = "ai"
            out["risk_level"] = "medium"
        elif any(safe in creator_low for safe in corporate_generators):
            out["source_category"] = "corporate"
            out["risk_level"] = "low"
        else:
            out["source_category"] = "unknown"
            out["risk_level"] = "medium"
            if creator:
                out["suspicious"].append(f"Unknown or unlisted PDF producer: {creator}")

        # modified date
        if creation and modified and creation != modified:
            out["suspicious"].append("Modified after original creation")
            out["risk_level"] = "high"

        # signature detection (quick)
        sig_present = detect_embedded_signature_bytes(b)
        out["signature"]["embedded"] = sig_present

        # If pyhanko available, attempt verification and attach summary (best-effort)
        if PYHANKO_AVAILABLE and sig_present:
            try:
                v = verify_pdf_signature_with_pyhanko_bytes(b)
                out["signature"]["pyhanko"] = v
                # if pyhanko says verified -> lower risk
                if v and v.get("verified_by_pyhanko"):
                    out["risk_level"] = "low"
            except Exception as e:
                out["signature"]["pyhanko_error"] = str(e)

        # signature absent -> for corporate we prefer signatures for critical docs
        if not sig_present and out["source_category"] not in ["corporate"]:
            out["suspicious"].append("No digital signature metadata found")

        # embedded fonts check (skip for corporate)
        if out["source_category"] in ["ai", "manual", "unknown"]:
            try:
                trailer = str(reader.trailer).lower()
                if "/font" not in trailer:
                    out["suspicious"].append("No embedded fonts → possibly scanned or AI-generated image PDF")
            except Exception:
                out["suspicious"].append("Could not determine embedded fonts")

    except Exception as e:
        out["error"] = str(e)
        out["source_category"] = "error"
        out["risk_level"] = "high"

    return out


# -----------------------
# Image forensics (unchanged)
# -----------------------
def extract_exif_from_bytes(b: bytes):
    try:
        return {k: str(v) for k, v in exifread.process_file(io.BytesIO(b), details=False).items()}
    except:
        return {}


def ela_score(pil_img):
    buf = io.BytesIO()
    pil_img.save(buf, "JPEG", quality=90)
    buf.seek(0)
    recompressed = Image.open(buf)
    ela = ImageChops.difference(pil_img, recompressed)
    ela = Image.eval(ela, lambda x: min(255, x * 12))
    return float(np.asarray(ela).mean())


def copy_move_score(pil_img):
    img = np.array(pil_img.convert("RGB"))
    gray = cv2.cvtColor(img, cv2.COLOR_RGB2GRAY)
    orb = cv2.ORB_create(1500)
    kp, des = orb.detectAndCompute(gray, None)
    if des is None:
        return 0.0
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=False)
    matches = bf.knnMatch(des, des, k=2)
    good = []
    for m, n in matches:
        if m.distance < 0.75 * n.distance and m.queryIdx != m.trainIdx:
            p1, p2 = kp[m.queryIdx].pt, kp[m.trainIdx].pt
            if np.linalg.norm(np.array(p1) - np.array(p2)) > 20:
                good.append(m)
    return min(1.0, len(good) / 100)


def image_forensics_from_bytes(b: bytes):
    pil_img = Image.open(io.BytesIO(b)).convert("RGB")
    gray = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2GRAY)
    ela = ela_score(pil_img)
    cm = copy_move_score(pil_img)
    blur = cv2.Laplacian(gray, cv2.CV_64F).var()
    exif = extract_exif_from_bytes(b)

    susp = []
    if not exif:
        susp.append("Missing EXIF")
    if ela > 20:
        susp.append("High ELA → edited")
    if cm > 0.5:
        susp.append("Copy-move pattern found")
    if blur < 15:
        susp.append("Unnaturally low sharpness")

    risk = "low"
    if ela > 40 or cm > 0.6:
        risk = "high"
    elif ela > 20 or cm > 0.3:
        risk = "medium"

    return {
        "type": "image",
        "ela_score": ela,
        "copy_move_score": cm,
        "blur": blur,
        "exif": exif,
        "suspicious": susp,
        "source_category": "image",
        "risk_level": risk,
    }


# -----------------------
# OCR helpers
# -----------------------
def extract_text_from_image_bytes(b: bytes) -> str:
    try:
        return pytesseract.image_to_string(Image.open(io.BytesIO(b)))
    except:
        return ""


def extract_text_from_pdf_bytes(b: bytes) -> str:
    try:
        pages = convert_from_bytes(b)
        texts = []
        for p in pages:
            texts.append(pytesseract.image_to_string(p))
        return "\n".join(texts)
    except Exception:
        return ""


# -----------------------
# Content checks + integration
# -----------------------
def content_checks_and_score(meta: dict, ocr_text: str):
    """
    Return (reasons, score_delta)
    - reasons: list of strings
    - score_delta: numeric points to add to tamper score (positive means more suspicious)
    """
    reasons = []
    score_delta = 0.0

    # keyword heuristics (fast)
    k_reasons = content_keyword_checks(ocr_text, meta)
    reasons.extend(k_reasons)
    score_delta += len(k_reasons) * 12  # each such issue adds 12 points

    # semantic similarity (optional)
    # We compare a concatenation of metadata strings (title/producer/author) vs OCR text,
    # if similarity is very low, increase suspicion.
    meta_text = " ".join(str(meta.get(k, "")) for k in ("Producer", "Creator", "Title", "Author", "Subject"))
    sim = semantic_similarity_score(meta_text, ocr_text)
    if sim is not None:
        # sim in [0..1], if low (<0.25) -> suspicious; if high (>0.7) -> consistent
        if sim < 0.25:
            reasons.append(f"Semantic mismatch between metadata and OCR text (sim={sim:.2f})")
            score_delta += 18
        elif sim < 0.45:
            reasons.append(f"Low semantic similarity (sim={sim:.2f})")
            score_delta += 8
        # if sim high, reduce suspicion slightly
        elif sim > 0.8:
            score_delta -= 5

    return reasons, score_delta


# -----------------------
# Scoring & aggregation (update)
# -----------------------
def aggregate(parts):
    reasons = []
    score = 0.0
    overall_risk = "low"
    category = "unknown"

    for p in parts:
        reasons.extend(p.get("suspicious", []))
        category = p.get("source_category", category)

        if p.get("type") == "pdf":
            score += len(p.get("suspicious", [])) * 12

            # signature effect: reduce score if valid signature
            sig = p.get("signature", {})
            if sig.get("embedded"):
                # if pyhanko indicated valid, greatly reduce score; else small negative impact
                py = sig.get("pyhanko")
                if py and py.get("verified_by_pyhanko"):
                    score -= 40
                    reasons.append("Cryptographic signature validated (pyhanko)")
                else:
                    # signature exists but not validated by pyhanko
                    score -= 5

        if p.get("type") == "image":
            score += p.get("ela_score", 0) / 5
            score += p.get("copy_move_score", 0) * 40
            if p.get("suspicious"):
                score += len(p.get("suspicious")) * 8

        # Risk aggregation from parts
        if p.get("risk_level") == "high":
            overall_risk = "high"
        elif p.get("risk_level") == "medium" and overall_risk != "high":
            overall_risk = "medium"

        # Content checks (NLP) per part if OCR available
        ocr = p.get("ocr_snippet", "") or ""
        meta = p.get("metadata", {})
        if ocr or meta:
            c_reasons, delta = content_checks_and_score(meta, ocr)
            if c_reasons:
                reasons.extend(c_reasons)
            score += delta

    score = round(min(max(score, 0.0), 100.0), 2)

    # derive final risk
    if score >= 70:
        overall_risk = "high"
    elif score >= 40 and overall_risk != "high":
        overall_risk = "medium"

    return {
        "tamper_score": score,
        "source_category": category,
        "risk_level": overall_risk,
        "reasons": reasons,
    }


# -----------------------
# API endpoint
# -----------------------
@app.post("/check-document")
async def check_document(file: UploadFile = File(...)):
    content = await file.read()
    fname = file.filename
    mime = mime_type_of_bytes(content)
    sha = sha256_of_bytes(content)
    parts = []

    if "pdf" in mime or fname.lower().endswith(".pdf"):
        pdf = analyze_pdf_bytes(content)
        # extract OCR snippet (may be slow) - keep for content checks
        pdf_text = extract_text_from_pdf_bytes(content)
        pdf["ocr_snippet"] = pdf_text[:300]
        parts.append(pdf)
    elif mime.startswith("image/"):
        img = image_forensics_from_bytes(content)
        img_text = extract_text_from_image_bytes(content)
        img["ocr_snippet"] = img_text[:300]
        parts.append(img)
    else:
        return JSONResponse({"error": f"Unsupported type {mime}"})

    return {
        "file_info": {"filename": fname, "mime": mime, "sha256": sha},
        "parts": parts,
        "aggregate": aggregate(parts),
    }
