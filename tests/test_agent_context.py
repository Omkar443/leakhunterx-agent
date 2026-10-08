import pytest
from agent.js.leak_detector import (
    extract_code_context,
    redact_secret_in_line,
    normalize_repo_relative_path,
    build_match_evidence_mask,
    EnterpriseLeakDetector,
)


def test_1_extract_code_context_bounded_lines():
    lines = [f"line {i}" for i in range(1, 100)]
    token = 'AKIA' + '1234567890123456'
    lines[49] = 'const API_KEY = "' + token + '";'
    source = "\n".join(lines)

    res = extract_code_context(
        content=source,
        line_number=50,
        raw_value=token,
        leak_type="Aws Access Key",
        context_before=30,
        context_after=30,
        max_chars=3000,
    )

    assert res["code_context"] is not None
    assert res["context_start_line"] == 20
    assert res["context_end_line"] == 80
    assert res["line_number"] == 50
    assert "AKIA[REDACTED_16_CHARS]" in res["code_context"]
    assert token not in res["code_context"]


def test_2_minified_single_line_js():
    token = 'AIzaSy' + 'D_TEST_SECRET_KEY_12345678'
    long_line = "var a=1;" * 500 + 'const SECRET="' + token + '";' + "var b=2;" * 500
    res = extract_code_context(
        content=long_line,
        position=4000,
        raw_value=token,
        leak_type="Google Api Key",
        max_chars=1000,
    )

    assert res["code_context"] is not None
    assert len(res["code_context"]) <= 1050
    assert "AIzaSy" in res["code_context"]
    assert "[REDACTED_" in res["code_context"]
    assert token not in res["code_context"]
    assert res["is_truncated"] is True


def test_3_secret_redaction_in_line():
    line = '  50 | const key = "SUPER_SECRET_TOKEN_999";'
    redacted = redact_secret_in_line(line, "SUPER_SECRET_TOKEN_999", evidence_mask="SUPE[REDACTED_18_CHARS]")
    assert redacted == '  50 | const key = "SUPE[REDACTED_18_CHARS]";'
    assert "SUPER_SECRET_TOKEN_999" not in redacted


def test_4_normalize_repo_relative_path():
    abs_path = "C:\\Users\\sahni\\Desktop\\myproject\\src\\config\\keys.ts"
    norm = normalize_repo_relative_path(abs_path)
    assert norm == "src/config/keys.ts"

    url_path = "https://example.com/static/js/main.chunk.js"
    assert normalize_repo_relative_path(url_path) == url_path


def test_5_detector_attaches_code_context():
    detector = EnterpriseLeakDetector()
    code = """
import config from './config';

export function getAwsClient() {
    const key = "SYNTHETIC_AWS_KEY";
    return key;
}
""".replace('SYNTHETIC_AWS_KEY', 'AKIA' + '1234567890123456')
    findings = detector.check_content(code)
    assert len(findings) > 0
    f = findings[0]
    assert "code_context" in f
    assert f["code_context"] is not None
    assert "AKIA[REDACTED_16_CHARS]" in f["code_context"]
    assert f["match_evidence_mask"] == "AKIA[REDACTED_16_CHARS]"
    assert f["match_length"] == 20
    assert 'AKIA' + '1234567890123456' not in f["code_context"]


def test_6_missing_source_returns_none_code_context():
    res = extract_code_context(None, line_number=10)
    assert res["code_context"] is None
    assert res["context_start_line"] is None


def test_7_match_evidence_mask():
    mask1 = build_match_evidence_mask("AIzaSy" + "D_1234567890abcdefghijklmnopqrst", "Google Api Key")
    assert mask1 == "AIzaSy[REDACTED_32_CHARS]"

    mask2 = build_match_evidence_mask("AKIA" + "1234567890123456", "Aws Access Key")
    assert mask2 == "AKIA[REDACTED_16_CHARS]"

    mask3 = build_match_evidence_mask("AIzaSy" + "D_YOUR_KEY_HERE_00000000000", "Google Api Key")
    assert "YOUR_KEY_HERE" not in mask3
    assert "REDACTED" in mask3
