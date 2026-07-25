"""Tests for PDF report generation."""

import os
import tempfile
import pytest

from pdf_report import generate_pdf_report


def test_generate_pdf_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        pdf_path = os.path.join(tmpdir, "test_report.pdf")

        mock_security_graph = {
            "summary": {
                "total_flows": 5,
                "sanitized_flows": 2,
                "unsanitized_flows": 3,
            },
            "subgraphs": {
                "auth": {"unprotected": [{"route": "/api/users", "file": "server.js"}]},
                "database": {"operations": [{"type": "write", "operation": "db.query"}]},
                "network": {"operations": []},
            }
        }

        mock_findings = [
            {
                "rule": "sql-injection-via-concat",
                "severity": "high",
                "title": "SQL Injection via Concatenation",
                "description": "User input concatenated into query string",
                "source": "SOURCE_HTTP_BODY",
                "sink": "SINK_DATABASE",
                "file": "routes/user.js",
                "recommendation": "Use parameterized queries or ORM",
            },
            {
                "rule": "database-write-without-validation",
                "severity": "medium",
                "title": "Database Write Without Validation",
                "description": "Unvalidated database write operation",
                "source": "req.body",
                "sink": "db.insert",
                "file": "controllers/auth.js",
                "recommendation": "Add Zod or Joi validation schema",
            }
        ]

        result = generate_pdf_report("TestRepo", mock_security_graph, mock_findings, pdf_path)

        assert result == pdf_path
        assert os.path.isfile(pdf_path)
        assert os.path.getsize(pdf_path) > 0
