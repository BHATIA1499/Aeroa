"""
Skuvvy Security Package
==============================
Enterprise-grade security layer for fashion retail data protection.

Modules
-------
encryption   — AES-256-GCM file & record encryption
audit        — Immutable audit logging (GDPR / SOC 2 compliant)
rbac         — Role-based access control (5-tier hierarchy)
rate_limiter — Per-endpoint rate limiting with burst protection
file_pipeline— Secure upload pipeline: validate → scan → encrypt → store
ai_privacy   — Data masking and Private Processing Mode for LLM calls
headers      — HTTP security headers, CSP, HSTS enforcement
validators   — Input sanitisation, injection prevention, type checking
"""
