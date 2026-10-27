"""Dashboard report controls stay wired to the real report API."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_email_activity_and_inbox_report_controls():
    script = (ROOT / "backend/dashboard/app.js").read_text()
    html = (ROOT / "backend/dashboard/index.html").read_text()
    assert "reportAction(m)" in script
    assert "reportAction(d)" in script
    assert '"Report possible data exposure"' in script
    assert 'window.confirm(`Report possible data exposure associated with ${domain}?' in script
    assert 'body: { email_id: m.id, confirmed_domain: domain }' in script
    assert 'error.status === 409' in script
    assert 'id="my-reports-list"' in html
    assert '"/website-reports/my?limit=100"' in script
    assert 'id="website-report-review"' in html
    assert '"/website-reports/review?limit=100"' in script
