"""
AI Privacy & Data Masking
==========================
Controls what data leaves Skuvvy servers when calling Claude.

Two modes
---------
Standard Mode (default)
  - Supplier names and vendor references are pseudonymised (SHA-256 alias)
  - Internal comments and free-text fields are stripped
  - SKU codes are passed through (needed for coherent analysis)
  - Numeric metrics are unmodified

Private Processing Mode (enterprise opt-in)
  - No individual SKU identifiers or names leave the server
  - Only aggregated category-level and KPI metrics are sent
  - Claude produces analysis from summary statistics only
  - Results are labelled "Private Processing Mode — aggregated data only"

Compliance note
---------------
Both modes are compatible with:
  - GDPR Art. 25 (Data Protection by Design)
  - Anthropic's usage policy (data is not used for model training)
  - ISO 27001 A.13.2 (information transfer policies)

Anthropic API — no-training commitment
---------------------------------------
Skuvvy uses the Anthropic API via the Messages API endpoint.
Per Anthropic's commercial API terms, data sent to this endpoint is
NOT used to train models.  This is enforced by the API agreement, not
by technical means on our side.
"""

import re
import copy
import hashlib
import logging

log = logging.getLogger(__name__)

# ── Fields to strip entirely from AI context ───────────────────────────────────
# These fields may contain PII, trade secrets, or sensitive supplier data
_STRIP_FIELDS = frozenset({
    "supplier", "vendor", "brand_owner", "manufacturer",
    "supplier_code", "vendor_id", "vendor_ref", "vendor_name",
    "internal_notes", "comments", "buyer_notes", "merchandiser_notes",
    "contact", "contract_price", "cost_price_negotiated",
    "factory", "country_of_origin", "ethical_audit_ref",
})

# ── Fields to pseudonymise (replace with hash alias) ──────────────────────────
_PSEUDONYMISE_FIELDS = frozenset({
    "supplier", "vendor", "vendor_name", "brand_owner",
})


# ── Pseudonymisation ───────────────────────────────────────────────────────────

def _alias(value: str, prefix: str = "VENDOR") -> str:
    """
    Deterministic pseudonym: same input always produces same alias
    within a session so AI responses remain coherent, but the real
    name cannot be recovered without the original value.
    """
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{h}"


# ── Standard mode masking ──────────────────────────────────────────────────────

def _mask_item(item: dict) -> dict:
    """Mask a single SKU/item dict for standard mode."""
    out = {}
    for k, v in item.items():
        key_lower = k.lower().replace("_", "").replace(" ", "")
        if any(f.replace("_", "") in key_lower for f in _STRIP_FIELDS):
            if any(f.replace("_", "") in key_lower for f in _PSEUDONYMISE_FIELDS):
                # Replace with pseudonym
                out[k] = _alias(str(v), "VENDOR") if v else None
            # else: strip entirely (don't include in output)
        else:
            out[k] = v
    return out


def mask_for_standard(analysis: dict) -> dict:
    """
    Standard mode: pseudonymise suppliers, strip internal comments.
    All numeric metrics and SKU codes are preserved.
    """
    masked = copy.deepcopy(analysis)

    # Mask items in lists
    for list_key in ("best_sellers", "markdown_risk", "reorder_alerts"):
        masked[list_key] = [_mask_item(item) for item in masked.get(list_key, [])]

    # Strip any top-level sensitive keys
    for field in _STRIP_FIELDS:
        masked.pop(field, None)

    masked["_privacy_mode"] = "standard"
    return masked


# ── Private Processing Mode ────────────────────────────────────────────────────

def mask_for_private(analysis: dict) -> dict:
    """
    Private Processing Mode: send ONLY aggregated KPIs and category-level
    summaries.  No individual SKU identifiers, supplier names, or
    product names leave the server.

    The AI will produce insights from summary statistics only.
    """
    kpis = analysis.get("kpis", {})
    cats = analysis.get("category_scorecard", [])
    meta = analysis.get("meta", {})

    # Category summaries — no product-level detail
    category_summaries = []
    for cat in cats:
        category_summaries.append({
            "health":           cat.get("health"),
            "revenue":          cat.get("revenue"),
            "avg_sell_through": cat.get("avg_sell_through"),
            "avg_margin_pct":   cat.get("avg_margin_pct"),
            "sku_count":        cat.get("sku_count"),
            "reorder_count":    cat.get("reorder_count"),
            "markdown_count":   cat.get("markdown_count"),
        })

    return {
        "kpis": kpis,
        "meta": {
            "sku_count":      meta.get("sku_count"),
            "category_count": meta.get("category_count"),
            "date_range":     meta.get("date_range"),
        },
        "categories": category_summaries,
        "reorder_count":   len(analysis.get("reorder_alerts", [])),
        "markdown_count":  len(analysis.get("markdown_risk",  [])),
        "_privacy_mode":   "private",
        "_note": (
            "PRIVATE PROCESSING MODE: Only aggregated metrics provided. "
            "No individual product identifiers, supplier names, or SKU codes "
            "are included in this analysis context. Base all insights on the "
            "aggregate statistics and category-level summaries only."
        ),
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def prepare_for_ai(analysis: dict, private_mode: bool = False) -> dict:
    """
    Prepare analysis data for sending to the Claude API.

    Parameters
    ----------
    analysis     : Raw analysis dict from the upload pipeline
    private_mode : If True, apply Private Processing Mode (no identifiers)

    Returns a masked copy — the original is never modified.
    """
    if private_mode:
        log.info("[AI_PRIVACY] Private Processing Mode active — aggregated data only")
        return mask_for_private(analysis)

    return mask_for_standard(analysis)


def private_mode_notice() -> str:
    """System prompt addition when Private Processing Mode is active."""
    return (
        "\n\n⚠️  PRIVATE PROCESSING MODE ACTIVE\n"
        "You are operating with aggregated data only. "
        "No supplier names, SKU codes, or product identifiers have been provided. "
        "Generate all insights, commentary, and recommendations from the "
        "aggregate KPIs and category summaries only. "
        "Do not invent or assume specific product names."
    )
