import os
import io
import json
import base64
from flask import Flask, request, redirect, render_template, url_for, flash, send_from_directory
import pandas as pd
from werkzeug.utils import secure_filename

# -------------------------
# Configuration
# -------------------------
app = Flask(__name__)
app.secret_key = "replace-this-with-a-secure-random-string"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200MB limit
ALLOWED_EXT = {"xlsx", "xls"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

# Columns you asked to keep (exact names)
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
    "source.@timestamp"
]

# -------------------------
# Routes
# -------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    """
    Upload Excel -> keep only KEEP_COLUMNS -> save filtered Excel -> compute aggregates -> render report.
    """
    if "file" not in request.files:
        flash("No file provided.")
        return redirect(url_for("index"))

    f = request.files["file"]
    if f.filename == "":
        flash("No file selected.")
        return redirect(url_for("index"))

    if not allowed_file(f.filename):
        flash("Allowed file types: .xlsx, .xls")
        return redirect(url_for("index"))

    safe_name = secure_filename(f.filename)
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    f.save(upload_path)

    # Read first sheet into DataFrame
    try:
        df = pd.read_excel(upload_path, engine="openpyxl")
    except Exception as e:
        flash(f"Could not read Excel: {e}")
        return redirect(url_for("index"))

    # Normalize columns (strip)
    df.columns = [str(c).strip() for c in df.columns]

    # Ensure all keep columns exist; create empty if missing
    for col in KEEP_COLUMNS:
        if col not in df.columns:
            df[col] = pd.NA

    # Build filtered DataFrame in the exact order of KEEP_COLUMNS
    filtered_df = df[KEEP_COLUMNS].copy()

    # Save filtered Excel for download
    base = os.path.splitext(safe_name)[0]
    filtered_name = f"{base}_filtered.xlsx"
    filtered_path = os.path.join(app.config["UPLOAD_FOLDER"], filtered_name)
    try:
        filtered_df.to_excel(filtered_path, index=False)
    except Exception as e:
        # non-fatal
        print("Could not save filtered file:", e)

    # Drop rows that don't have rule id (we only care about rows with a rule id)
    analysis_df = filtered_df.dropna(subset=["source.rule.id"]).copy()

    # Convert rule level to numeric when possible
    try:
        analysis_df["source.rule.level"] = pd.to_numeric(analysis_df["source.rule.level"], errors="coerce")
    except Exception:
        pass

    # -------------------------
    # Chart 1: counts per source.rule.id (top N)
    # -------------------------
    counts_by_rule = analysis_df["source.rule.id"].value_counts().to_dict()
    avg_level_by_rule = analysis_df.groupby("source.rule.id")["source.rule.level"].mean().fillna(0).to_dict()
    description_by_rule = analysis_df.groupby("source.rule.id")["source.rule.description"].first().fillna("").to_dict()

    TOP_N = 25
    sorted_rules = sorted(counts_by_rule.items(), key=lambda x: -x[1])[:TOP_N]
    chart1_labels = [r[0] for r in sorted_rules]
    chart1_values = [int(r[1]) for r in sorted_rules]
    chart1_descriptions = [description_by_rule.get(rid, "") for rid in chart1_labels]
    chart1_avg_levels = [float(avg_level_by_rule.get(rid, 0)) if not pd.isna(avg_level_by_rule.get(rid, 0)) else 0 for rid in chart1_labels]

    # -------------------------
    # Chart 2: source.data.action counts by source.rule.level
    # -------------------------
    grouped_action = analysis_df.groupby(["source.rule.level", "source.data.action"]).size().unstack(fill_value=0)
    grouped_action = grouped_action.sort_index()
    chart2_levels = [str(int(l)) if pd.notna(l) and float(l).is_integer() else str(l) for l in grouped_action.index.tolist()]
    chart2_actions = grouped_action.columns.tolist()
    chart2_action_counts = {}
    for action in chart2_actions:
        key = action if pd.notna(action) else "Unknown"
        chart2_action_counts[key] = [int(grouped_action.loc[idx, action]) for idx in grouped_action.index]

    # -------------------------
    # Chart 3: unique source.data.srcip counts per source.rule.level
    # (for each rule level, count distinct srcip)
    # -------------------------
    try:
        unique_srcip_by_level = analysis_df.groupby("source.rule.level")["source.data.srcip"].nunique()
        unique_srcip_by_level = unique_srcip_by_level.sort_index()
        chart3_levels = [str(int(l)) if pd.notna(l) and float(l).is_integer() else str(l) for l in unique_srcip_by_level.index.tolist()]
        chart3_values = [int(v) for v in unique_srcip_by_level.values.tolist()]
    except Exception:
        # fallback empty
        chart3_levels = []
        chart3_values = []

    # -------------------------
    # Summary (table)
    # -------------------------
    summary_rows = []
    for rule_id, cnt in sorted(counts_by_rule.items(), key=lambda x: -x[1]):
        summary_rows.append({
            "rule_id": rule_id,
            "description": str(description_by_rule.get(rule_id, "") or ""),
            "avg_level": float(avg_level_by_rule.get(rule_id, 0)) if not pd.isna(avg_level_by_rule.get(rule_id, 0)) else 0,
            "count": int(cnt)
        })

    # Save summary CSV and XLSX
    summary_df = pd.DataFrame(summary_rows)
    csv_name = f"{base}_summary.csv"
    xlsx_name = f"{base}_summary.xlsx"
    csv_path = os.path.join(app.config["UPLOAD_FOLDER"], csv_name)
    xlsx_path = os.path.join(app.config["UPLOAD_FOLDER"], xlsx_name)
    try:
        summary_df.to_csv(csv_path, index=False)
        summary_df.to_excel(xlsx_path, index=False)
    except Exception as e:
        print("Could not save summary files:", e)

    # build payload for template
    payload = {
        "chart1": {
            "labels": chart1_labels,
            "values": chart1_values,
            "descriptions": chart1_descriptions,
            "avg_levels": chart1_avg_levels
        },
        "chart2": {
            "levels": chart2_levels,
            "actions": list(chart2_action_counts.keys()),
            "action_counts": chart2_action_counts
        },
        "chart3": {
            "levels": chart3_levels,
            "values": chart3_values
        },
        "summary": summary_rows
    }

    # Save payload for debug (optional)
    payload_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{base}_payload.json")
    try:
        with open(payload_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
    except Exception:
        pass

    # Pass download URLs to template
    return render_template(
        "report.html",
        payload=payload,
        filename=safe_name,
        csv_url=url_for("download_file", filename=csv_name),
        xlsx_url=url_for("download_file", filename=xlsx_name),
        filtered_xlsx_url=url_for("download_file", filename=filtered_name)
    )

# Endpoint to serve files in uploads
@app.route("/uploads/<path:filename>", methods=["GET"])
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

# Endpoint to save canvas images posted from client (chart export)
@app.route("/save_chart", methods=["POST"])
def save_chart():
    data = request.get_json(force=True)
    name = data.get("name", "chart.png")
    data_url = data.get("data", "")
    if not data_url.startswith("data:image"):
        return {"ok": False, "error": "Invalid data url"}, 400

    header, b64 = data_url.split(",", 1)
    ext = "png"
    if "image/jpeg" in header or "image/jpg" in header:
        ext = "jpg"
    safe_name = secure_filename(name)
    if not safe_name.lower().endswith(f".{ext}"):
        safe_name = f"{safe_name}.{ext}"
    out_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)

    try:
        decoded = base64.b64decode(b64)
        with open(out_path, "wb") as fh:
            fh.write(decoded)
    except Exception as e:
        return {"ok": False, "error": str(e)}, 500

    return {"ok": True, "filename": safe_name, "url": url_for("download_file", filename=safe_name)}

# -------------------------
# Run server
# -------------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
