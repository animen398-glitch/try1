from gui.tab_recon import ReconTabMixin


def test_dynamic_endpoint_format_tolerates_missing_status():
    line = ReconTabMixin._format_dynamic_endpoint({
        "method": "GET",
        "status": None,
        "path": "/api/items",
        "host": "example.test",
    })

    assert "GET" in line
    assert "  -  " in line
    assert "/api/items" in line
    assert "example.test" in line


def test_dynamic_endpoint_format_tolerates_empty_values():
    line = ReconTabMixin._format_dynamic_endpoint({
        "method": None,
        "status": "",
        "path": None,
        "host": None,
    })

    assert "GET" in line
    assert "  -  " in line
    assert "/" in line


def test_dynamic_endpoint_format_tolerates_non_numeric_status():
    line = ReconTabMixin._format_dynamic_endpoint({
        "method": "POST",
        "status": "cached",
        "path": "/graphql",
        "host": "api.example.test",
    })

    assert "POST" in line
    assert "cached" in line
    assert "/graphql" in line
