"""
Threadlytics — Flask backend (Phase 1: Auth + Supabase)
========================================================
Routes:
  Public
    GET  /                    → marketing site
    GET  /login               → login page
    GET  /signup              → signup page
    GET  /health              → health check

  Auth
    POST /auth/signup         → create account
    POST /auth/login          → sign in, set session
    POST /auth/logout         → clear session
    GET  /auth/me             → current user info

  App (requires login)
    GET  /dashboard           → main app UI
    POST /api/upload          → parse & store CSV/XLSX
    GET  /api/analysis        → return latest analysis
    GET  /api/uploads         → list user's uploads
    POST /api/chat            → standard AI chat
    POST /api/chat/stream     → SSE streaming chat
    GET  /api/quick-insights  → 3-bullet AI insights

  Stripe webhooks
    POST /webhooks/stripe     → handle subscription events
"""

import os
import io
import json
import uuid
import math
import functools
from datetime import datetime, timezone

import pandas as pd
from flask import (Flask, request, jsonify, session,
                   Response, send_from_directory, redirect, url_for)
from flask_cors import CORS
from dotenv import load_dotenv
import anthropic
from supabase import create_client, Client
import stripe

load_dotenv()

# ── App setup ────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"
CORS(app, supports_credentials=True)

# ── Clients ───────────────────────────────────────────────────
ai_client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
MODEL = "claude-sonnet-4-5"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# Plan limits
PLAN_LIMITS = {
    "trial":   {"skus": 50,     "ai_msgs": 20},
    "starter": {"skus": 200,    "ai_msgs": 50},
    "growth":  {"skus": 999999, "ai_msgs": 999999},
    "studio":  {"skus": 999999, "ai_msgs": 999999},
}

# ═══════════════════════════════════════════════════════════════
# AUTH HELPERS
# ═══════════════════════════════════════════════════════════════

def get_user_db() -> Client:
    """Return a Supabase client authenticated as the current user (uses their JWT)."""
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token", "")
    if not access_token:
        return supabase
    client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    try:
        client.auth.set_session(access_token, refresh_token)
    except Exception:
        pass
    return client


def get_current_user():
    """Return profile dict from Supabase, or None."""
    uid = session.get("user_id")
    if not uid:
        return None
    # Use session-cached profile for every request — avoids a DB round-trip
    # and survives if PostgREST grants haven't been applied yet.
    cached = session.get("user_profile")
    if cached and cached.get("id") == uid:
        return cached
    try:
        db = get_user_db()
        res = db.table("profiles").select("*").eq("id", uid).single().execute()
        if res.data:
            session["user_profile"] = res.data
            return res.data
    except Exception:
        pass
    # Graceful fallback: construct minimal profile from session
    return {
        "id": uid,
        "email": session.get("user_email", ""),
        "full_name": session.get("user_name", ""),
        "plan": session.get("user_plan", "trial"),
        "trial_ends": session.get("user_trial_ends"),
        "ai_messages_used": 0,
    }


def require_auth(f):
    """Decorator: redirect to /login if not authenticated."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect("/login")
        return f(*args, user=user, **kwargs)
    return decorated


def check_plan_limit(user, resource):
    """Return (allowed: bool, message: str)."""
    plan = user.get("plan", "trial")

    # Trial expiry check
    trial_ends = user.get("trial_ends")
    if plan == "trial" and trial_ends:
        ends = datetime.fromisoformat(trial_ends.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > ends:
            return False, "Your free trial has ended. Please upgrade to continue."

    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["trial"])

    if resource == "ai_msg":
        # Reset monthly counter if needed
        reset_at = user.get("ai_messages_reset", "")
        if reset_at:
            reset_dt = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if now.year > reset_dt.year or now.month > reset_dt.month:
                get_user_db().table("profiles").update({
                    "ai_messages_used": 0,
                    "ai_messages_reset": now.isoformat()
                }).eq("id", user["id"]).execute()
                user["ai_messages_used"] = 0

        used = user.get("ai_messages_used", 0)
        allowed = limit["ai_msgs"]
        if used >= allowed:
            return False, f"You've used all {allowed} AI messages this month. Upgrade to get more."

    return True, ""


# ═══════════════════════════════════════════════════════════════
# DATA ANALYSIS ENGINE  (same as before, cleaned up)
# ═══════════════════════════════════════════════════════════════

# ── Column finder: normalises spaces, underscores, case ───────
def _col(df, *candidates):
    """Case-insensitive, space/underscore-insensitive column matcher."""
    normalised = {c.lower().replace(" ", "").replace("_", ""): c for c in df.columns}
    for cand in candidates:
        key = cand.lower().replace(" ", "").replace("_", "")
        if key in normalised:
            return normalised[key]
    return None

def _safe_float(val, default=0.0):
    try:
        f = float(val)
        return default if math.isnan(f) else f
    except (TypeError, ValueError):
        return default

def _clean_numeric(series):
    """
    Handle every real-world numeric format:
    - Currency with commas:  "£44,400"  "$2,500.00"  (Excel/Sheets quoted export)
    - Currency symbols only: £1500  $2500  €3100
    - Percentage strings:    29.8%  45%  100%
    - Plain numbers and already-numeric columns
    """
    if pd.api.types.is_numeric_dtype(series):
        return pd.to_numeric(series, errors="coerce").fillna(0)
    cleaned = (series.astype(str).str.strip()
               .str.replace(r"[£$€¥₹,\s]", "", regex=True)   # currency symbols + thousands commas
               .str.replace(r"%$", "", regex=True)              # trailing %
               .replace({"nan": "0", "None": "0", "": "0", "-": "0", "N/A": "0", "n/a": "0"}))
    return pd.to_numeric(cleaned, errors="coerce").fillna(0)

def _fix_decimal_percent(series, col_name):
    """
    Google Sheets and some ERP exports store percentages as 0–1 decimals.
    e.g. SellThrough = 0.298 instead of 29.8
    Detect and multiply by 100 automatically.
    """
    PCT_HINTS = {"sellthrough", "sellthroughpct", "st", "marginpct", "margin",
                 "returnrate", "fullpriceratio", "fpratio"}
    normalised = col_name.lower().replace(" ", "").replace("_", "")
    if not any(h in normalised for h in PCT_HINTS):
        return series
    nums = pd.to_numeric(series, errors="coerce").dropna()
    if len(nums) > 0 and (nums <= 1.5).all() and (nums > 0).any():
        return (series * 100).round(2)
    return series

def _best_sheet(file_obj, filename):
    """
    For multi-sheet Excel files, pick the sheet that has the most
    recognisable merchandising columns rather than blindly taking sheet 0.
    """
    KEY_COLS = {"sku", "productcode", "itemcode", "revenue", "sales",
                "unitssold", "units", "qty", "stockonhand", "stock"}
    xl = pd.ExcelFile(file_obj)
    best_sheet, best_score = xl.sheet_names[0], -1
    for name in xl.sheet_names:
        try:
            df = xl.parse(name, nrows=3)
            cols = {c.lower().replace(" ", "").replace("_", "") for c in df.columns}
            score = len(cols & KEY_COLS)
            if score > best_score:
                best_score, best_sheet = score, name
        except Exception:
            continue
    return xl.parse(best_sheet)

def parse_upload(file_obj, filename):
    """
    Universal file parser — handles every format users actually export:
      Excel   .xlsx / .xls   (from Excel, Google Sheets, Numbers)
      ODS     .ods            (LibreOffice / OpenOffice)
      CSV     .csv            (any app, any delimiter, with/without BOM)
      TSV     .tsv / .txt     (tab-delimited from reporting tools)

    Robustness built in:
      - UTF-8 BOM stripped automatically (Apple Numbers CSV export)
      - Delimiter auto-detected (comma, semicolon, tab, pipe)
      - Empty leading/trailing rows and columns dropped
      - Multi-sheet Excel: picks the sheet with most data columns
    """
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext in ("xlsx", "xls"):
        # Read bytes for multi-sheet detection
        raw = file_obj.read() if hasattr(file_obj, "read") else file_obj
        df = _best_sheet(io.BytesIO(raw), filename)

    elif ext == "ods":
        raw = file_obj.read() if hasattr(file_obj, "read") else file_obj
        df = pd.read_excel(io.BytesIO(raw), engine="odf")

    else:
        # CSV / TSV / TXT — auto-detect delimiter + BOM
        raw = file_obj.read() if hasattr(file_obj, "read") else file_obj
        # Detect and strip BOM
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        text = raw.decode("utf-8", errors="replace")

        # Note: currency symbols in Excel/Sheets exports are always quoted ("£44,400")
        # so pandas correctly parses them as strings. _clean_numeric strips £,$,€
        # and commas from those strings after parsing.
        try:
            df = pd.read_csv(
                io.StringIO(text),
                sep=None,            # auto-detect: comma, semicolon, tab, pipe
                engine="python",
                skip_blank_lines=True,
                encoding_errors="replace",
            )
        except Exception:
            # Sniffer can fail on unusual files — fall back to comma delimiter
            df = pd.read_csv(
                io.StringIO(text),
                sep=",",
                skip_blank_lines=True,
                encoding_errors="replace",
            )

    # ── Post-load cleanup ──────────────────────────────────────
    # Strip column name whitespace
    df.columns = [str(c).strip() for c in df.columns]
    # Drop entirely-empty columns and rows (Google Sheets ghost cells)
    df = df.dropna(axis=1, how="all").dropna(axis=0, how="all")
    # Drop unnamed columns (Unnamed: 3, Unnamed: 4 …)
    df = df[[c for c in df.columns if not str(c).startswith("Unnamed:")]]
    # Reset index after row drops
    df = df.reset_index(drop=True)

    return df

def analyse(df):
    # ── Expanded column detection — covers all app export formats ─
    col_sku   = _col(df, "SKU","sku","ProductCode","product_code","ItemCode","item_code",
                         "Item Code","Product Code","Style","StyleCode","style_code")
    col_units = _col(df, "UnitsSold","units_sold","Units","Qty","Quantity","qty",
                         "Units Sold","Sales Units","SalesUnits","Pieces","pieces")
    col_rev   = _col(df, "Revenue","revenue","Sales","SalesValue","sales_value",
                         "Total Revenue","TotalRevenue","Net Sales","NetSales",
                         "Total Sales","TotalSales","Turnover","turnover")
    col_stock = _col(df, "StockOnHand","stock_on_hand","Stock","OnHand","on_hand",
                         "Stock On Hand","CurrentStock","current_stock","Inventory","inventory",
                         "ClosingStock","closing_stock","Units On Hand")
    col_cost  = _col(df, "CostPrice","cost_price","Cost","UnitCost","unit_cost",
                         "Cost Price","Buying Price","buying_price","COGS")
    col_margin= _col(df, "MarginPct","margin_pct","Margin","GrossMarginPct",
                         "gross_margin_pct","GM%","GM Pct","Gross Margin","GrossMargin",
                         "Margin %","Margin%","GP%")
    col_st    = _col(df, "SellThrough","sell_through","SellThroughPct","ST","S/T",
                         "Sell Through","Sell Through %","SellThru","sell_thru","STR")
    col_cover = _col(df, "StockCoverWeeks","stock_cover_weeks","CoverWeeks","cover_weeks",
                         "Weeks Cover","WeeksCover","Cover","WOS","wos","Weeks of Stock")
    col_cat   = _col(df, "Category","category","Department","Dept","dept",
                         "Product Type","ProductType","Division","Class","Subclass")
    col_chan  = _col(df, "Channel","channel","SalesChannel","sales_channel",
                         "Store","Region","Location","Market")
    col_week  = _col(df, "Week","week","WeekNumber","week_number","Period","period",
                         "Week No","WeekNo","Trading Week","Wk")
    col_name  = _col(df, "ProductName","product_name","Name","Description","Desc",
                         "Product Name","Product Description","Style Name","StyleName")
    col_brand = _col(df, "Brand","brand","BrandName","brand_name","Label","Supplier")
    col_buy   = _col(df, "BuyQty","buy_qty","OpeningStock","opening_stock","InitialStock",
                         "initial_stock","IntakeQty","intake_qty","Opening Stock","Buy Qty")
    col_fp    = _col(df, "FullPriceSales","full_price_sales","FPSales","fp_sales",
                         "Full Price Revenue","FullPriceRevenue","FP Revenue")

    if not all([col_sku, col_units, col_rev]):
        missing = [n for c,n in [(col_sku,"SKU"),(col_units,"UnitsSold"),(col_rev,"Revenue")] if not c]
        found = list(df.columns[:10])
        raise ValueError(
            f"Missing required columns: {', '.join(missing)}. "
            f"Found columns: {', '.join(str(c) for c in found)}{'...' if len(df.columns)>10 else ''}. "
            f"Threadlytics needs at least SKU, UnitsSold/Units/Qty, and Revenue/Sales columns."
        )

    # ── Clean numerics — strips £$€, commas, % signs ──────────
    for col in [col_units, col_rev, col_stock, col_cost, col_fp, col_buy]:
        if col:
            df[col] = _clean_numeric(df[col])

    # ── Fix decimal percentages (Google Sheets / ERP exports) ──
    for col, name in [(col_margin, "MarginPct"), (col_st, "SellThrough"), (col_cover, "StockCoverWeeks")]:
        if col:
            df[col] = _clean_numeric(df[col])
            df[col] = _fix_decimal_percent(df[col], name)

    agg = {col_units: "sum", col_rev: "sum"}
    for c in [col_stock, col_cost, col_margin, col_st, col_cover,
              col_cat, col_chan, col_name, col_brand, col_fp, col_buy]:
        if c:
            agg[c] = "last" if c in [col_stock, col_st, col_cover] else \
                     "first" if c in [col_cat, col_chan, col_name, col_brand, col_buy] else "sum"

    sku_df = df.groupby(col_sku, as_index=False).agg(agg)
    total_rev   = _safe_float(sku_df[col_rev].sum())
    total_units = _safe_float(sku_df[col_units].sum())
    sku_count   = len(sku_df)
    avg_st      = _safe_float(sku_df[col_st].mean()) if col_st else 0.0
    avg_margin  = _safe_float(sku_df[col_margin].mean()) if col_margin else 0.0
    avg_cover   = _safe_float(sku_df[col_cover].mean()) if col_cover else 0.0
    gross_profit= total_rev * avg_margin / 100

    # Best sellers
    best = sku_df.sort_values(col_rev, ascending=False).head(20)
    best_sellers = []
    for _, r in best.iterrows():
        e = {"sku": str(r[col_sku]), "revenue": round(_safe_float(r[col_rev]), 2),
             "units": round(_safe_float(r[col_units]))}
        if col_name:   e["name"]         = str(r[col_name])
        if col_cat:    e["category"]     = str(r[col_cat])
        if col_st:     e["sell_through"] = round(_safe_float(r[col_st]), 1)
        if col_margin: e["margin_pct"]   = round(_safe_float(r[col_margin]), 1)
        if col_stock:  e["stock"]        = round(_safe_float(r[col_stock]))
        best_sellers.append(e)

    # Reorder alerts
    reorders = []
    sev_map = {"CRITICAL": 0, "URGENT": 1, "REORDER": 2}
    for _, r in sku_df.iterrows():
        stock = _safe_float(r[col_stock]) if col_stock else None
        cover = _safe_float(r[col_cover]) if col_cover else None
        st    = _safe_float(r[col_st]) if col_st else None
        if stock == 0 or (cover is not None and cover <= 4) or (st is not None and st >= 70 and (stock is None or stock < 20)):
            urgency = "CRITICAL" if (stock == 0 or (cover is not None and cover <= 1)) else \
                      "URGENT"   if (cover is not None and cover <= 2) else "REORDER"
            e = {"sku": str(r[col_sku]), "urgency": urgency,
                 "revenue": round(_safe_float(r[col_rev]), 2)}
            if col_name:  e["name"]         = str(r[col_name])
            if col_cat:   e["category"]     = str(r[col_cat])
            if col_stock: e["stock"]        = round(stock) if stock is not None else None
            if col_cover: e["cover_weeks"]  = round(cover, 1) if cover is not None else None
            if col_st:    e["sell_through"] = round(st, 1) if st is not None else None
            reorders.append(e)
    reorders.sort(key=lambda x: (sev_map[x["urgency"]], -x["revenue"]))

    # Markdown risk
    markdowns = []
    sev_md = {"CLEARANCE": 0, "DEEP": 1, "TACTICAL": 2}
    if col_st:
        for _, r in sku_df.iterrows():
            st = _safe_float(r[col_st])
            stock = _safe_float(r[col_stock]) if col_stock else None
            if st < 30 and (stock is None or stock > 0):
                sev = "CLEARANCE" if st < 15 else "DEEP" if st < 22 else "TACTICAL"
                depth = "40–50%" if st < 15 else "25–35%" if st < 22 else "15–20%"
                e = {"sku": str(r[col_sku]), "severity": sev, "sell_through": round(st, 1),
                     "recommended_depth": depth, "revenue": round(_safe_float(r[col_rev]), 2)}
                if col_name: e["name"]     = str(r[col_name])
                if col_cat:  e["category"] = str(r[col_cat])
                markdowns.append(e)
    markdowns.sort(key=lambda x: (sev_md[x["severity"]], -x["revenue"]))

    # Category scorecard
    categories = []
    if col_cat:
        for cat, grp in sku_df.groupby(col_cat):
            cat_rev = _safe_float(grp[col_rev].sum())
            cat_st  = _safe_float(grp[col_st].mean()) if col_st else None
            cat_mg  = _safe_float(grp[col_margin].mean()) if col_margin else None
            health  = ("STRONG" if cat_st >= 40 else "HEALTHY" if cat_st >= 25
                       else "AT RISK" if cat_st >= 15 else "CRITICAL") if cat_st else "UNKNOWN"
            e = {"category": str(cat), "revenue": round(cat_rev, 2),
                 "units": round(_safe_float(grp[col_units].sum())), "sku_count": len(grp), "health": health}
            if cat_st is not None: e["avg_sell_through"] = round(cat_st, 1)
            if cat_mg is not None: e["avg_margin_pct"]   = round(cat_mg, 1)
            categories.append(e)
        categories.sort(key=lambda x: -x["revenue"])

    # Weekly trend
    weekly = []
    if col_week:
        wg = df.groupby(col_week)[col_rev].sum().reset_index().sort_values(col_week)
        weekly = [{"week": str(r[col_week]), "revenue": round(_safe_float(r[col_rev]), 2)} for _, r in wg.iterrows()]

    # Channel split
    channels = []
    if col_chan:
        cg = df.groupby(col_chan)[col_rev].sum().reset_index().sort_values(col_rev, ascending=False)
        channels = [{"channel": str(r[col_chan]),
                     "revenue": round(_safe_float(r[col_rev]), 2),
                     "share_pct": round(_safe_float(r[col_rev]) / total_rev * 100, 1) if total_rev else 0}
                    for _, r in cg.iterrows()]

    return {
        "meta": {"sku_count": sku_count, "analysed_at": datetime.utcnow().isoformat()},
        "kpis": {
            "total_revenue": round(total_rev, 2),
            "total_units": round(total_units),
            "gross_profit": round(gross_profit, 2),
            "avg_sell_through": round(avg_st, 1),
            "avg_margin_pct": round(avg_margin, 1),
            "avg_cover_weeks": round(avg_cover, 1),
            "reorder_count": len(reorders),
            "markdown_risk_count": len(markdowns),
            "critical_oos_count": sum(1 for r in reorders if r["urgency"] == "CRITICAL"),
        },
        "weekly_trend": weekly,
        "best_sellers": best_sellers,
        "reorder_alerts": reorders[:50],
        "markdown_risk": markdowns[:50],
        "category_scorecard": categories,
        "channel_split": channels,
    }


def build_system_prompt(analysis):
    k = analysis.get("kpis", {})
    return f"""You are a senior fashion merchandiser and buying director inside Threadlytics.

TRADING DATA
============
Revenue: £{k.get('total_revenue',0):,.0f} | Units: {k.get('total_units',0):,.0f}
Gross Profit: £{k.get('gross_profit',0):,.0f} | Sell-Through: {k.get('avg_sell_through',0):.1f}%
Gross Margin: {k.get('avg_margin_pct',0):.1f}% | Stock Cover: {k.get('avg_cover_weeks',0):.1f} wks
SKUs: {analysis.get('meta',{}).get('sku_count',0)} | Reorder alerts: {k.get('reorder_count',0)} | Markdown risk: {k.get('markdown_risk_count',0)}

TOP REORDERS: {json.dumps(analysis.get('reorder_alerts',[])[:8])}
TOP MARKDOWN RISK: {json.dumps(analysis.get('markdown_risk',[])[:8])}
BEST SELLERS: {json.dumps(analysis.get('best_sellers',[])[:8])}
CATEGORIES: {json.dumps(analysis.get('category_scorecard',[]))}

Answer like a buying director — specific SKUs, real numbers, clear actions. Never generic."""


# ═══════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return send_from_directory(".", "threadlytics_fixed.html")

@app.route("/login")
def login_page():
    if get_current_user():
        return redirect("/dashboard")
    return send_from_directory(".", "login.html")

@app.route("/signup")
def signup_page():
    if get_current_user():
        return redirect("/dashboard")
    return send_from_directory(".", "signup.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


# ═══════════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/auth/signup", methods=["POST"])
def auth_signup():
    body = request.get_json(silent=True) or {}
    email    = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "").strip()
    name     = (body.get("full_name") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    try:
        # Use admin API to create a pre-confirmed user (no email verification step)
        res = supabase.auth.admin.create_user({
            "email": email,
            "password": password,
            "email_confirm": True,
            "user_metadata": {"full_name": name},
        })
        if not res.user:
            return jsonify({"error": "Signup failed — please try again"}), 400

        # Sign in immediately to get a JWT for the session
        sign_in = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if sign_in.user and sign_in.session:
            from datetime import timezone
            trial_ends = (datetime.now(timezone.utc) + __import__('datetime').timedelta(days=14)).isoformat()
            session["user_id"]         = sign_in.user.id
            session["user_email"]      = email
            session["user_name"]       = name
            session["user_plan"]       = "trial"
            session["user_trial_ends"] = trial_ends
            session["access_token"]    = sign_in.session.access_token
            session["refresh_token"]   = sign_in.session.refresh_token
            return jsonify({"ok": True, "redirect": "/dashboard"})
        return jsonify({"error": "Account created — please log in"}), 200
    except Exception as e:
        msg = str(e)
        if "already registered" in msg.lower() or "already been registered" in msg.lower() or "duplicate" in msg.lower():
            return jsonify({"error": "An account with this email already exists"}), 409
        app.logger.error(f"Signup error: {e}", exc_info=True)
        return jsonify({"error": "Signup failed — please try again"}), 500


@app.route("/auth/login", methods=["POST"])
def auth_login():
    body = request.get_json(silent=True) or {}
    email    = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        if res.user and res.session:
            meta = res.user.user_metadata or {}
            session["user_id"]         = res.user.id
            session["user_email"]      = email
            session["user_name"]       = meta.get("full_name", email.split("@")[0])
            session["user_plan"]       = "trial"
            session["access_token"]    = res.session.access_token
            session["refresh_token"]   = res.session.refresh_token
            return jsonify({"ok": True, "redirect": "/dashboard"})
        return jsonify({"error": "Invalid email or password"}), 401
    except Exception as e:
        msg = str(e).lower()
        if "invalid" in msg or "credentials" in msg:
            return jsonify({"error": "Invalid email or password"}), 401
        app.logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({"error": "Login failed — please try again"}), 500


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    session.clear()
    return jsonify({"ok": True, "redirect": "/login"})


@app.route("/auth/me")
def auth_me():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({
        "id":        user["id"],
        "email":     user["email"],
        "full_name": user.get("full_name", ""),
        "plan":      user.get("plan", "trial"),
        "trial_ends": user.get("trial_ends"),
        "ai_messages_used": user.get("ai_messages_used", 0),
    })


# ═══════════════════════════════════════════════════════════════
# PROTECTED APP ROUTES
# ═══════════════════════════════════════════════════════════════

@app.route("/dashboard")
@require_auth
def dashboard(user):
    return send_from_directory(".", "dashboard.html")


@app.route("/api/upload", methods=["POST"])
@require_auth
def upload(user):
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400

    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ("csv", "xlsx", "xls"):
        return jsonify({"error": "Unsupported format. Please upload CSV, XLSX, or XLS."}), 400

    try:
        file_bytes = f.read()
        df = parse_upload(io.BytesIO(file_bytes), f.filename)
        result = analyse(df)

        # Check SKU limit for plan
        sku_count = result["meta"]["sku_count"]
        plan = user.get("plan", "trial")
        sku_limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["trial"])["skus"]
        if sku_count > sku_limit:
            return jsonify({
                "error": f"Your {plan.title()} plan supports up to {sku_limit} SKUs. This file has {sku_count}. Please upgrade.",
                "upgrade_required": True
            }), 402

        # Persist to Supabase
        upload_row = get_user_db().table("uploads").insert({
            "user_id":   user["id"],
            "filename":  f.filename,
            "sku_count": sku_count,
            "analysis":  result,
        }).execute()

        upload_id = upload_row.data[0]["id"] if upload_row.data else None
        session["current_upload_id"] = upload_id

        return jsonify({
            "status": "ok",
            "upload_id": upload_id,
            "filename": f.filename,
            "sku_count": sku_count,
            "kpis": result["kpis"],
        })

    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    except Exception as e:
        app.logger.error(f"Upload error: {e}", exc_info=True)
        return jsonify({"error": "Failed to parse file. Please check the format."}), 500


@app.route("/api/analysis")
@require_auth
def get_analysis(user):
    upload_id = request.args.get("upload_id") or session.get("current_upload_id")
    db = get_user_db()
    if upload_id:
        try:
            res = db.table("uploads").select("analysis") \
                .eq("id", upload_id).eq("user_id", user["id"]).single().execute()
            if res.data:
                return jsonify(res.data["analysis"])
        except Exception:
            pass

    # Fallback: return latest upload
    try:
        res = db.table("uploads").select("analysis") \
            .eq("user_id", user["id"]).order("created_at", desc=True).limit(1).execute()
        if res.data:
            return jsonify(res.data[0]["analysis"])
    except Exception:
        pass

    return jsonify({"error": "No data uploaded yet"}), 404


@app.route("/api/uploads")
@require_auth
def list_uploads(user):
    try:
        res = get_user_db().table("uploads") \
            .select("id, filename, sku_count, created_at") \
            .eq("user_id", user["id"]) \
            .order("created_at", desc=True).limit(20).execute()
        return jsonify({"uploads": res.data or []})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_analysis_for_user(user, upload_id=None):
    """Helper to fetch analysis JSON from Supabase."""
    try:
        db = get_user_db()
        uid = upload_id or session.get("current_upload_id")
        if uid:
            res = db.table("uploads").select("analysis, id") \
                .eq("id", uid).eq("user_id", user["id"]).single().execute()
            if res.data:
                return res.data["analysis"], res.data["id"]

        res = db.table("uploads").select("analysis, id") \
            .eq("user_id", user["id"]).order("created_at", desc=True).limit(1).execute()
        if res.data:
            return res.data[0]["analysis"], res.data[0]["id"]
    except Exception:
        pass
    return None, None


def _increment_ai_usage(user):
    get_user_db().table("profiles").update(
        {"ai_messages_used": (user.get("ai_messages_used", 0) + 1)}
    ).eq("id", user["id"]).execute()


@app.route("/api/chat", methods=["POST"])
@require_auth
def chat(user):
    allowed, msg = check_plan_limit(user, "ai_msg")
    if not allowed:
        return jsonify({"error": msg, "upgrade_required": True}), 402

    body = request.get_json(silent=True) or {}
    user_msg  = (body.get("message") or "").strip()
    upload_id = body.get("upload_id")
    if not user_msg:
        return jsonify({"error": "Empty message"}), 400

    analysis, uid = _get_analysis_for_user(user, upload_id)
    if not analysis:
        return jsonify({"error": "No data uploaded yet. Please upload a trading file first."}), 404

    # Fetch recent chat history from Supabase
    db = get_user_db()
    try:
        hist_res = db.table("chat_messages") \
            .select("role, content").eq("user_id", user["id"]) \
            .eq("upload_id", uid).order("created_at", desc=False).limit(20).execute()
        history = [{"role": r["role"], "content": r["content"]} for r in (hist_res.data or [])]
    except Exception:
        history = []

    history.append({"role": "user", "content": user_msg})

    try:
        response = ai_client.messages.create(
            model=MODEL, max_tokens=1024,
            system=build_system_prompt(analysis),
            messages=history,
        )
        reply = response.content[0].text

        # Persist both messages
        db.table("chat_messages").insert([
            {"user_id": user["id"], "upload_id": uid, "role": "user",      "content": user_msg},
            {"user_id": user["id"], "upload_id": uid, "role": "assistant", "content": reply},
        ]).execute()

        _increment_ai_usage(user)
        return jsonify({"reply": reply})

    except anthropic.APIError as e:
        app.logger.error(f"Anthropic error: {e}")
        return jsonify({"error": "AI service error. Please try again."}), 502


@app.route("/api/chat/stream", methods=["POST"])
@require_auth
def chat_stream(user):
    allowed, msg = check_plan_limit(user, "ai_msg")
    if not allowed:
        def err():
            yield f"data: {json.dumps({'error': msg, 'upgrade_required': True})}\n\n"
        return Response(err(), mimetype="text/event-stream")

    body = request.get_json(silent=True) or {}
    user_msg  = (body.get("message") or "").strip()
    upload_id = body.get("upload_id")

    analysis, uid = _get_analysis_for_user(user, upload_id)
    if not analysis:
        def err():
            yield f"data: {json.dumps({'error': 'No data uploaded yet'})}\n\n"
        return Response(err(), mimetype="text/event-stream")

    stream_db = get_user_db()
    try:
        hist_res = stream_db.table("chat_messages") \
            .select("role, content").eq("user_id", user["id"]) \
            .eq("upload_id", uid).order("created_at", desc=False).limit(20).execute()
        history = [{"role": r["role"], "content": r["content"]} for r in (hist_res.data or [])]
    except Exception:
        history = []

    history.append({"role": "user", "content": user_msg})

    def generate():
        full_reply = []
        try:
            with ai_client.messages.stream(
                model=MODEL, max_tokens=1024,
                system=build_system_prompt(analysis),
                messages=history,
            ) as stream:
                for text in stream.text_stream:
                    full_reply.append(text)
                    yield f"data: {json.dumps({'delta': text})}\n\n"

            reply = "".join(full_reply)
            stream_db.table("chat_messages").insert([
                {"user_id": user["id"], "upload_id": uid, "role": "user",      "content": user_msg},
                {"user_id": user["id"], "upload_id": uid, "role": "assistant", "content": reply},
            ]).execute()
            _increment_ai_usage(user)
            yield f"data: {json.dumps({'done': True})}\n\n"

        except Exception as e:
            app.logger.error(f"Stream error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/quick-insights")
@require_auth
def quick_insights(user):
    analysis, _ = _get_analysis_for_user(user)
    if not analysis:
        return jsonify({"insights": [
            "Upload your trading CSV or Excel to unlock AI insights.",
            "Track sell-through, reorder alerts, and markdown risk in one place.",
            "Ask the AI anything about your range — grounded in your actual numbers.",
        ]})

    k = analysis["kpis"]
    reorders  = analysis.get("reorder_alerts", [])
    markdowns = analysis.get("markdown_risk", [])
    cats      = analysis.get("category_scorecard", [])

    prompt = f"""Based on this trading data, generate exactly 3 concise action-oriented insights for a fashion buyer. Each one sentence, starting with an action verb. Return as a JSON array of strings only.

Revenue £{k.get('total_revenue',0):,.0f} | ST {k.get('avg_sell_through',0):.1f}% | Margin {k.get('avg_margin_pct',0):.1f}%
{k.get('reorder_count',0)} reorder alerts, {k.get('critical_oos_count',0)} OOS
Top reorder: {reorders[0] if reorders else 'none'}
Top markdown: {markdowns[0] if markdowns else 'none'}
Best category: {cats[0] if cats else 'none'}
Weakest category: {cats[-1] if len(cats)>1 else 'none'}

Return ONLY a JSON array, no markdown."""

    try:
        res = ai_client.messages.create(
            model=MODEL, max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        insights = json.loads(res.content[0].text.strip())
        return jsonify({"insights": insights[:3]})
    except Exception:
        return jsonify({"insights": [
            f"Raise POs immediately for {k.get('critical_oos_count',0)} out-of-stock SKUs before revenue is lost.",
            f"Review {k.get('markdown_risk_count',0)} slow-selling SKUs for tactical markdowns to protect margin.",
            f"Overall sell-through of {k.get('avg_sell_through',0):.1f}% indicates overbought range — tighten next season's OTB.",
        ]})


# ═══════════════════════════════════════════════════════════════
# STRIPE WEBHOOKS
# ═══════════════════════════════════════════════════════════════

@app.route("/webhooks/stripe", methods=["POST"])
def stripe_webhook():
    payload = request.get_data()
    sig     = request.headers.get("Stripe-Signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # Idempotency check
    try:
        existing = supabase.table("stripe_events").select("id").eq("id", event["id"]).execute()
        if existing.data:
            return jsonify({"ok": True})
        supabase.table("stripe_events").insert({"id": event["id"], "type": event["type"]}).execute()
    except Exception:
        pass

    etype = event["type"]
    data  = event["data"]["object"]

    PRICE_TO_PLAN = {
        os.environ.get("STRIPE_PRICE_STARTER", ""): "starter",
        os.environ.get("STRIPE_PRICE_GROWTH",  ""): "growth",
        os.environ.get("STRIPE_PRICE_STUDIO",  ""): "studio",
    }

    if etype == "checkout.session.completed":
        customer_id = data.get("customer")
        sub_id      = data.get("subscription")
        email       = data.get("customer_details", {}).get("email", "")
        price_id    = data.get("line_items", {}).get("data", [{}])[0].get("price", {}).get("id", "")
        plan        = PRICE_TO_PLAN.get(price_id, "starter")

        try:
            supabase.table("profiles").update({
                "plan": plan,
                "stripe_customer_id": customer_id,
                "stripe_subscription_id": sub_id,
            }).eq("email", email.lower()).execute()
        except Exception as e:
            app.logger.error(f"Webhook profile update error: {e}")

    elif etype in ("customer.subscription.updated", "customer.subscription.deleted"):
        customer_id = data.get("customer")
        status      = data.get("status")
        plan        = "trial" if (etype == "customer.subscription.deleted" or status == "canceled") else \
                      PRICE_TO_PLAN.get(data.get("items", {}).get("data", [{}])[0].get("price", {}).get("id", ""), "starter")
        try:
            supabase.table("profiles").update({"plan": plan}) \
                .eq("stripe_customer_id", customer_id).execute()
        except Exception as e:
            app.logger.error(f"Webhook subscription error: {e}")

    supabase.table("stripe_events").update({"processed": True}).eq("id", event["id"]).execute()
    return jsonify({"ok": True})


# ── Serve static assets ───────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    return "", 204


if __name__ == "__main__":
    port  = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "development") == "development"
    print(f"\n🧵 Threadlytics running → http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=debug)
