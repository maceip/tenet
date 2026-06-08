"""Shared CORS helpers for local tenet HTTP adapters."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler


def send_cors_headers(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")
    handler.send_header("Access-Control-Max-Age", "86400")


def handle_cors_preflight(handler: BaseHTTPRequestHandler) -> None:
    handler.send_response(204)
    send_cors_headers(handler)
    handler.end_headers()
