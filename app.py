import os
import re
import json
import base64
import fitz  # PyMuPDF
import io
from datetime import datetime
from xhtml2pdf import pisa
from PIL import Image, ImageOps
from flask import make_response
from flask import url_for
import pdfplumber
import pandas as pd

from flask import Flask, request, render_template, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from PIL import Image, ImageEnhance
from flask import render_template, url_for, redirect, flash
from flask import request, send_file
import asyncio
import pdfkit
from flask import send_file, make_response
try:
    from pyppeteer import launch as pyppeteer_launch
except Exception:
    pyppeteer_launch = None
# ---------------- CONFIG ----------------
app = Flask(__name__)
app.jinja_env.globals.update(zip=zip)
app.secret_key = "replace-with-secure-key"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB limit
ALLOWED_EXT = {"xlsx", "xls", "csv", "pdf"}

KEEP_COLUMNS = [
    "source.predecoder.timestamp",
    "source.data.protocol",
    "source.data.srcip",
    "source.data.dstport",
    "source.data.action",
    "source.data.srcport",
    "source.data.dstip",
    "source.rule.level",
    "source.rule.description",
    "source.rule.groups",
    "source.rule.id",
    "source.decoder.parent",
    "source.decoder.name",
    "source.input.type",
    "source.@timestamp",
]

# ---------------- HELPERS ----------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def extract_pdf_summary(pdf_path):
    """Extract rule_id, description, level, count from Wazuh PDF."""
    text = ""
    try:
        with pdfplumber.open(pdf_path) as pdf:
            for p in pdf.pages:
                t = p.extract_text()
                if t:
                    text += t + "\n"
    except Exception as e:
        print("PDF read error:", e)
        return pd.DataFrame(columns=["Rule ID", "Description", "Level", "Count"])

    pattern = re.compile(r"(\d{2,7})\s+(.+?)\s+(\d{1,2})\s+(\d{1,20})(?:\s|$)")
    matches = pattern.findall(text)
    rows = []
    for rid, desc, lvl, cnt in matches:
        rows.append({
            "Rule ID": rid.strip(),
            "Description": " ".join(desc.split()),
            "Level": int(lvl),
            "Count": int(cnt)
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df = df.drop_duplicates().sort_values("Count", ascending=False)
    return df


ILLEGAL_CHARS_RE = re.compile(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]')

def _sanitize(val):
    if isinstance(val, str):
        return ILLEGAL_CHARS_RE.sub('', val)
    return val

def save_summary(df, base):
    csv_path = os.path.join(UPLOAD_FOLDER, f"{base}_summary.csv")
    xlsx_path = os.path.join(UPLOAD_FOLDER, f"{base}_summary.xlsx")
    df.to_csv(csv_path, index=False)
    df_clean = df.applymap(_sanitize)
    df_clean.to_excel(xlsx_path, index=False)
    return csv_path, xlsx_path

def remove_black_background(pil_img, threshold=60):
    """
    Convert dark/black background to pure white while keeping chart colors.
    """
    pil_img = pil_img.convert("RGBA")
    datas = pil_img.getdata()
    new_data = []
    
    for item in datas:
        r, g, b, a = item

        # If pixel is black or near-black → make it white
        if r < threshold and g < threshold and b < threshold:
            new_data.append((255, 255, 255, 255))
        else:
            new_data.append((r, g, b, 255))

    pil_img.putdata(new_data)
    return pil_img.convert("RGB")

def extract_images_and_raster_from_pdf(pdf_path, dest_folder, rasterize_pages=True, lighten_images=True):
    """
    Extract embedded images and rasterize PDF pages.
    Returns list of saved filenames (just the filename, not full path).
    - dest_folder must exist.
    - lighten_images: try to convert dark backgrounds to light for display.
    """
    saved = []
    seen_hashes = set()

    try:
        doc = fitz.open(pdf_path)
    except Exception as e:
        print("Could not open PDF:", e)
        return saved

    base = os.path.splitext(os.path.basename(pdf_path))[0]
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")

    def _avg_hash(pil_img, size=(8,8)):
        g = pil_img.convert("L").resize(size, Image.LANCZOS)
        pixels = list(g.getdata())
        avg = sum(pixels) / len(pixels)
        return tuple(1 if p > avg else 0 for p in pixels)

    def _is_mostly_dark(pil_img, threshold=60, fraction_non_dark=0.02):
        gray = pil_img.convert("L")
        data = gray.getdata()
        total = len(data)
        non_dark = sum(1 for v in data if v > threshold)
        return (non_dark / total) < fraction_non_dark

    def _replace_black_with_white(pil_img, black_thresh=40):
        img = pil_img.convert("RGB")
        pixels = list(img.getdata())
        new_pixels = []
        for r,g,b in pixels:
            if r < black_thresh and g < black_thresh and b < black_thresh:
                new_pixels.append((255,255,255))
            else:
                new_pixels.append((r,g,b))
        img.putdata(new_pixels)
        return img

    def _autofix_image(pil_img):
        try:
            img = ImageOps.autocontrast(pil_img)
            img = ImageEnhance.Sharpness(img).enhance(1.05)
            return img
        except Exception:
            return pil_img

    # 1) embedded images
    for p_i in range(len(doc)):
        page = doc[p_i]
        images = page.get_images(full=True)
        if not images:
            continue
        for idx, imginfo in enumerate(images, start=1):
            try:
                xref = imginfo[0]
                info = doc.extract_image(xref)
                img_bytes = info["image"]
                ext = info.get("ext", "png")
                name = f"{base}_p{p_i+1}_emb{idx}_{ts}.{ext}"
                path = os.path.join(dest_folder, name)
                with open(path, "wb") as fh:
                    fh.write(img_bytes)

                pil = Image.open(path).convert("RGB")
                pil = remove_black_background(pil)

                if lighten_images:
                    if _is_mostly_dark(pil):
                        pil = _replace_black_with_white(pil)
                        pil = ImageOps.autocontrast(pil)

                h = _avg_hash(pil)
                if h in seen_hashes:
                    try: os.remove(path)
                    except: pass
                    continue
                seen_hashes.add(h)

                outname = os.path.splitext(name)[0] + ".png"
                outpath = os.path.join(dest_folder, outname)
                pil.save(outpath, "PNG")
                try:
                    if os.path.exists(path) and path != outpath:
                        os.remove(path)
                except: pass

                saved.append(outname)
            except Exception as e:
                print("embed extract error:", e)
                continue

    # 2) rasterize pages (fallback and to capture vector charts)
    if rasterize_pages:
        for p_i in range(len(doc)):
            try:
                page = doc[p_i]
                mat = fitz.Matrix(2.0, 2.0)  # 2x zoom
                pix = page.get_pixmap(matrix=mat, alpha=False)
                name = f"{base}_p{p_i+1}_raster_{ts}.png"
                path = os.path.join(dest_folder, name)
                pix.save(path)

                pil = Image.open(path).convert("RGB")
                pil = remove_black_background(pil)
                if lighten_images and _is_mostly_dark(pil):
                    pil = _replace_black_with_white(pil)
                    pil = _autofix_image(pil)

                h = _avg_hash(pil)
                if h in seen_hashes:
                    try: os.remove(path)
                    except: pass
                    continue
                seen_hashes.add(h)

                pil.save(path, "PNG")
                saved.append(name)
            except Exception as e:
                print("rasterize page error:", e)
                continue

    # keep order, unique
    unique = []
    seen = set()
    for s in saved:
        if s not in seen:
            unique.append(s)
            seen.add(s)
    return unique

# Helper: make HTML absolute so wkhtmltopdf/Chromium can load images & links
def make_html_absolute(html: str) -> str:
    base = request.url_root.rstrip('/')
    html = html.replace('href="/', f'href="{base}/')
    html = html.replace('src="/', f'src="{base}/')
    html = html.replace('href="uploads/', f'href="{base}/uploads/')
    html = html.replace('src="uploads/', f'src="{base}/uploads/')
    return html

# Helper: headless Edge/Chrome — renders Bootstrap exactly like the web view
BROWSER_CANDIDATES = [
    os.environ.get("CHROME_PATH", ""),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge",
]

def try_headless_browser(html_str: str, out_path: str) -> bool:
    import subprocess
    import tempfile
    from pathlib import Path

    browser = next((b for b in BROWSER_CANDIDATES if b and os.path.exists(b)), None)
    if not browser:
        app.logger.warning("No Edge/Chrome executable found for headless PDF")
        return False

    # Point local images at files on disk so the browser doesn't call back into this server
    root = Path(app.root_path)
    html_str = html_str.replace('src="/uploads/', f'src="{(root / UPLOAD_FOLDER).as_uri()}/')
    html_str = html_str.replace('src="/static/', f'src="{(root / "static").as_uri()}/')

    html_file = os.path.join(app.config["UPLOAD_FOLDER"], f"_print_{datetime.utcnow().strftime('%Y%m%dT%H%M%S%f')}.html")
    with open(html_file, "w", encoding="utf-8") as fh:
        fh.write(html_str)

    profile_dir = tempfile.mkdtemp(prefix="pdfprofile_")
    try:
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--allow-file-access-from-files",
            f"--user-data-dir={profile_dir}",
            "--no-pdf-header-footer",
            "--print-to-pdf-no-header",
            "--virtual-time-budget=10000",
            f"--print-to-pdf={os.path.abspath(out_path)}",
            Path(os.path.abspath(html_file)).as_uri(),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        ok = os.path.exists(out_path) and os.path.getsize(out_path) > 0
        if not ok:
            app.logger.warning("headless browser produced no PDF (exit %s): %s",
                               proc.returncode, (proc.stderr or "")[-2000:])
        return ok
    except Exception as e:
        app.logger.warning("headless browser PDF failed: %s", e)
        return False
    finally:
        try:
            os.remove(html_file)
        except OSError:
            pass
        import shutil
        shutil.rmtree(profile_dir, ignore_errors=True)

# Helper: try pdfkit (wkhtmltopdf)
def try_pdfkit(html_str: str, out_path: str) -> bool:
    try:
        # If wkhtmltopdf is in a custom path set env var WKHTMLTOPDF_PATH to the exe
        wk = os.environ.get("WKHTMLTOPDF_PATH")
        if wk:
            config = pdfkit.configuration(wkhtmltopdf=wk)
            pdfkit.from_string(html_str, out_path, configuration=config, options={
                "enable-local-file-access": None,
                "quiet": ""
            })
        else:
            pdfkit.from_string(html_str, out_path, options={"enable-local-file-access": None, "quiet": ""})
        return True
    except Exception as e:
        app.logger.warning("pdfkit/wkhtmltopdf failed: %s", e)
        return False

# Helper: pyppeteer fallback
async def _generate_pdf_pyppeteer(html_str: str, out_path: str):
    if pyppeteer_launch is None:
        raise RuntimeError("pyppeteer is not installed")
    try:
        browser = await pyppeteer_launch(args=['--no-sandbox', '--disable-setuid-sandbox'])
        page = await browser.newPage()
        # set content and wait for networkidle so images load
        await page.setContent(html_str, waitUntil='networkidle0', timeout=30000)
        await page.pdf({
            'path': out_path,
            'format': 'A4',
            'printBackground': True,
            'margin': {'top': '12mm', 'bottom': '12mm', 'left': '10mm', 'right': '10mm'}
        })
        await browser.close()
    except Exception as e:
        # Try to download Chromium if it's missing
        try:
            import pyppeteer.chromium_downloader
            app.logger.info("Attempting to download Chromium for pyppeteer...")
            pyppeteer.chromium_downloader.download_chromium()
            # Retry after download
            browser = await pyppeteer_launch(args=['--no-sandbox', '--disable-setuid-sandbox'])
            page = await browser.newPage()
            await page.setContent(html_str, waitUntil='networkidle0', timeout=30000)
            await page.pdf({
                'path': out_path,
                'format': 'A4',
                'printBackground': True,
                'margin': {'top': '12mm', 'bottom': '12mm', 'left': '10mm', 'right': '10mm'}
            })
            await browser.close()
        except Exception as retry_e:
            raise RuntimeError(f"pyppeteer failed even after Chromium download attempt: {retry_e}")

def try_pyppeteer(html_str: str, out_path: str) -> bool:
    try:
        # Create new event loop if needed (for Windows compatibility)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        loop.run_until_complete(_generate_pdf_pyppeteer(html_str, out_path))
        return True
    except Exception as e:
        app.logger.error("pyppeteer PDF generation failed: %s", e)
        return False

# Helper: xhtml2pdf fallback (already imported as pisa)
def try_xhtml2pdf(html_str: str, out_path: str) -> bool:
    try:
        with open(out_path, "wb") as result_file:
            pisa_status = pisa.CreatePDF(
                html_str,
                dest=result_file,
                encoding='utf-8'
            )
        if pisa_status.err:
            app.logger.warning("xhtml2pdf had errors: %s", pisa_status.err)
            return False
        return True
    except Exception as e:
        app.logger.error("xhtml2pdf PDF generation failed: %s", e)
        return False
# ---------------- ROUTES ----------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    excel_file = request.files.get("excel_file")
    pdf_file = request.files.get("pdf_file")

    if not excel_file or not pdf_file:
        flash("Please upload both Excel and PDF files.")
        return redirect(url_for("index"))

    excel_name = secure_filename(excel_file.filename)
    pdf_name = secure_filename(pdf_file.filename)
    excel_path = os.path.join(app.config["UPLOAD_FOLDER"], excel_name)
    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], pdf_name)
    excel_file.save(excel_path)
    pdf_file.save(pdf_path)

    # Parse Excel (keep columns defined in KEEP_COLUMNS)
    ext = excel_name.rsplit(".", 1)[1].lower()
    if ext in ("xlsx", "xls"):
        df = pd.read_excel(excel_path, engine="openpyxl")
    else:
        df = pd.read_csv(excel_path)
    df.columns = [str(c).strip() for c in df.columns]
    
    # Map columns with underscore prefix (_source.*) to columns without underscore (source.*)
    # Create a mapping from original column names (with _) to target column names (without _)
    column_mapping = {}
    for col in df.columns:
        if col.startswith("_source."):
            # Remove leading underscore: "_source.xxx" -> "source.xxx"
            target_col = col[1:]  # Remove first character (_)
            if target_col in KEEP_COLUMNS:
                column_mapping[col] = target_col
    
    # Rename columns that have underscore prefix
    df = df.rename(columns=column_mapping)
    
    # Ensure all KEEP_COLUMNS exist (fill with NA if missing)
    for col in KEEP_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA
    
    # Create filtered dataframe with columns in the order specified by KEEP_COLUMNS
    # and with column names without underscores
    filtered_df = df[KEEP_COLUMNS].copy()
    base = os.path.splitext(excel_name)[0]
    filtered_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{base}_filtered.xlsx")
    try:
        filtered_df.to_excel(filtered_path, index=False)
    except Exception:
        pass

    analysis_df = filtered_df.dropna(subset=["source.rule.id"]).copy()
    analysis_df["source.rule.level"] = pd.to_numeric(analysis_df["source.rule.level"], errors="coerce")

    # Chart data: actions by level
    if {"source.rule.level", "source.data.action"}.issubset(analysis_df.columns):
        grouped = (analysis_df.groupby(["source.rule.level", "source.data.action"])
                   .size().unstack(fill_value=0).sort_index())
        grouped = grouped.rename(columns=lambda c: str(c) if pd.notna(c) else "Unknown")
        chart_levels = [str(int(l)) if pd.notna(l) and float(l).is_integer() else str(l) for l in grouped.index]
        actions = grouped.columns.tolist()
        action_counts = {a: [int(grouped.iloc[i][a]) for i in range(len(grouped.index))] for a in actions}
    else:
        chart_levels, actions, action_counts = [], [], {}

    # Extract PDF summary table (text)
    pdf_summary = extract_pdf_summary(pdf_path)  # keep using your parser helper
    csv_path, xlsx_path = save_summary(pdf_summary, base)

    # Extract images from PDF (embedded + raster)
    extracted_files = extract_images_and_raster_from_pdf(pdf_path, app.config["UPLOAD_FOLDER"],
                                                        rasterize_pages=True, lighten_images=True)
    # Keep only first 2 images (you said there are two)
    extracted_files = extracted_files[:2]

    # Build (url, filename) pairs so template doesn't have to call zip()
    images_and_files = []
    for fn in extracted_files:
        images_and_files.append((url_for("download_file", filename=fn), fn))

    payload = {
        "chart": {"levels": chart_levels, "actions": actions, "action_counts": action_counts},
        "pdf_summary": pdf_summary.head(200).to_dict(orient="records"),
        "pdf_images": [p[0] for p in images_and_files]
    }

    return render_template(
        "report.html",
        payload=payload,
        filename_excel=excel_name,
        filename_pdf=pdf_name,
        filtered_xlsx_url=url_for("download_file", filename=f"{base}_filtered.xlsx"),
        csv_url=url_for("download_file", filename=f"{base}_summary.csv"),
        xlsx_url=url_for("download_file", filename=f"{base}_summary.xlsx"),
        images_and_files=images_and_files,
        hide_images=False,  # show images in the web view
        hide_header=False,  # show title/logo bar in the web view
    )


@app.route("/uploads/<path:filename>", methods=["GET"])
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)

@app.route("/download_report", methods=["GET"])
def download_report():
    """
    Usage: /download_report?pdf=<pdf_filename>&excel=<excel_filename>
    Rebuilds report context and attempts to generate PDF using wkhtmltopdf or pyppeteer.
    """
    pdf_name = request.args.get("pdf")
    excel_name = request.args.get("excel")

    if not pdf_name:
        return "Missing ?pdf=your_report.pdf parameter", 400

    # Build context by re-running the parsing helpers (like /upload does)
    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], pdf_name)
    if not os.path.exists(pdf_path):
        return f"PDF file not found on server: {pdf_name}", 404

    # 1) build pdf_summary
    try:
        pdf_summary = extract_pdf_summary(pdf_path)
    except Exception as e:
        app.logger.warning("extract_pdf_summary failed: %s", e)
        pdf_summary = pd.DataFrame(columns=["Rule ID", "Description", "Level", "Count"])

    base_excel = os.path.splitext(excel_name)[0] if excel_name else os.path.splitext(pdf_name)[0]
    # 2) ensure summary files exist (optional)
    try:
        csv_path, xlsx_path = save_summary(pdf_summary, base_excel)
    except Exception:
        csv_path = xlsx_path = ""

    # 3) Extract images for the PDF render (same as upload flow)
    images_and_files = []
    try:
        extracted = extract_images_and_raster_from_pdf(
            pdf_path,
            app.config["UPLOAD_FOLDER"],
            rasterize_pages=True,
            lighten_images=True,
        )
        extracted = [f for f in extracted if f.lower().endswith(('.png', '.jpg', '.jpeg'))][:2]
        for fn in extracted:
            images_and_files.append((url_for("download_file", filename=fn), fn))
    except Exception as e:
        app.logger.warning("extract_images_and_raster_from_pdf failed: %s", e)
        images_and_files = []

    # 4) Build the same payload you render in /upload
    payload = {
        "chart": {"levels": [], "actions": [], "action_counts": {}},
        "pdf_summary": pdf_summary.head(200).to_dict(orient="records"),
        "pdf_images": [p[0] for p in images_and_files]
    }

    # 5) Render template into HTML string (same template you already use)
    rendered_html = render_template(
        "report.html",
        payload=payload,
        filename_excel=excel_name or "",
        filename_pdf=pdf_name or "",
        filtered_xlsx_url=url_for("download_file", filename=f"{base_excel}_filtered.xlsx") if excel_name else "",
        csv_url=url_for("download_file", filename=f"{base_excel}_summary.csv") if excel_name else "",
        xlsx_url=url_for("download_file", filename=f"{base_excel}_summary.xlsx") if excel_name else "",
        images_and_files=images_and_files,
        hide_images=False,  # show images in the PDF render
        hide_header=True   # hide the top title/logo bar only in the PDF download
    )

    # 6) Save to a temp output file
    out_name = f"{base_excel}_report_{datetime.utcnow().strftime('%Y%m%dT%H%M%S')}.pdf"
    out_path = os.path.join(app.config["UPLOAD_FOLDER"], out_name)

    # 7) Prefer headless Edge/Chrome: same rendering as the browser view
    if try_headless_browser(rendered_html, out_path):
        return send_from_directory(app.config["UPLOAD_FOLDER"], out_name, as_attachment=True)

    # Make links absolute so the remaining pdf engines can fetch them
    html_abs = make_html_absolute(rendered_html)

    # 8) Try pdfkit/wkhtmltopdf first
    if try_pdfkit(html_abs, out_path):
        return send_from_directory(app.config["UPLOAD_FOLDER"], out_name, as_attachment=True)

    # 9) Fallback to pyppeteer (Chromium)
    if pyppeteer_launch:
        if try_pyppeteer(html_abs, out_path):
            return send_from_directory(app.config["UPLOAD_FOLDER"], out_name, as_attachment=True)

    # 10) Fallback to xhtml2pdf (pisa) - already imported
    if try_xhtml2pdf(html_abs, out_path):
        return send_from_directory(app.config["UPLOAD_FOLDER"], out_name, as_attachment=True)

    # 11) If all fail, save HTML fallback and return error
    fallback_html = os.path.join(app.config["UPLOAD_FOLDER"], f"{base_excel}_report_fallback.html")
    with open(fallback_html, "w", encoding="utf-8") as fh:
        fh.write(html_abs)

    errmsg = (
        "PDF generation failed (wkhtmltopdf/pdfkit, pyppeteer, and xhtml2pdf all unavailable or failed).\n\n"
        f"A fallback HTML file was written to: {fallback_html}\n\n"
        "Fixes:\n"
        "- Install wkhtmltopdf and set WKHTMLTOPDF_PATH env var to the executable or add it to PATH.\n"
        "- Or install pyppeteer (pip install pyppeteer) and allow Chromium download.\n"
        "- Or ensure xhtml2pdf is properly installed (pip install xhtml2pdf).\n"
    )
    app.logger.error(errmsg)
    return make_response(errmsg, 500)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
