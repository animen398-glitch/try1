"""Тест-кейсы для валидации работы парсеров"""
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.anti_detect_engine import AntiDetectSession
from core.api_key_extractor import ApiKeyExtractor
from core.design_analyzer import DesignAnalyzer
from core.frontend_cloner import FrontendCloner
from utils.cloudflare_tools import detect_cloudflare, detect_waf, is_rate_limited
from utils.file_compression import FileCompressor


def test_api_key_patterns():
    extractor = ApiKeyExtractor()
    test_html = """
    var config = {
        apiKey: 'AIzaSyDummyTestKeyForValidation123456789',
        api_key: 'testkey_abcdefghijklmnopqrstuvwxyz',
    };
    var awsKey = 'AKIAIOSFODNN7EXAMPLE';
    """
    found = {}
    for finding in extractor._scanner.scan_text(test_html):
        found.setdefault(finding['type'], []).append(finding['match'])

    print(f"[PASS] API patterns — найдено типов: {len(found)}")
    for k, v in found.items():
        print(f"  {k}: {v}")
    return len(found) > 0


def test_cloudflare_detection():
    cf_html = "<html><body>cf-browser-verification Checking your browser</body></html>"
    normal_html = "<html><body>Hello World</body></html>"

    assert detect_cloudflare(cf_html), "Должен детектировать CF"
    assert not detect_cloudflare(normal_html), "Ложное срабатывание"
    print("[PASS] Cloudflare detection")
    return True


def test_rate_limit_detection():
    assert is_rate_limited(429, "")
    assert is_rate_limited(503, "")
    assert is_rate_limited(200, "too many requests")
    assert not is_rate_limited(200, "Hello World")
    print("[PASS] Rate limit detection")
    return True


def test_file_compression():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / 'test.txt'
        test_file.write_text("test content", encoding='utf-8')

        zip_path = str(Path(tmpdir) / 'output.zip')
        result = FileCompressor.files_to_zip([str(test_file)], zip_path)

        assert Path(result).exists(), "ZIP не создан"
        with zipfile.ZipFile(result) as zf:
            assert 'test.txt' in zf.namelist()

    print("[PASS] File compression")
    return True


def test_url_normalization():
    extractor = ApiKeyExtractor()
    extractor.set_target_url("example.com")
    assert extractor.target_url == "https://example.com"

    extractor.set_target_url("http://already.set.com")
    assert extractor.target_url == "http://already.set.com"
    print("[PASS] URL normalization")
    return True


def test_waf_detection():
    cf_html = "this page uses cloudflare protection"
    assert detect_waf(cf_html) == 'Cloudflare'

    clean_html = "welcome to our website"
    assert detect_waf(clean_html) is None
    print("[PASS] WAF detection")
    return True


def test_design_analyzer():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        (tmp / 'style.css').write_text("""
            body {
                font-family: 'Roboto', sans-serif;
                color: #333333;
                background-color: rgb(255, 255, 255);
            }
            h1 { font-family: 'Open Sans', Arial, sans-serif; color: #FF5733; }
            .card { border-color: #abc; background: hsl(200, 50%, 75%); }
        """, encoding='utf-8')

        (tmp / 'index.html').write_text("""
            <html><head>
            <style>
                .btn { color: #1A73E8; font-family: 'Montserrat'; }
                @font-face { font-family: 'CustomFont'; src: url('custom.woff2'); }
            </style>
            </head><body></body></html>
        """, encoding='utf-8')

        analyzer = DesignAnalyzer()
        analyzer.configure(tmpdir)
        result = analyzer.analyze()

        assert result['status'] == 'Success', f"Ожидали Success, получили: {result['status']}"
        assert len(result['colors']) > 0, "Цвета не найдены"
        assert len(result['fonts']) > 0, "Шрифты не найдены"

        color_values = [c['value'] for c in result['colors']]
        assert '#333333' in color_values, "Hex #333333 не найден"
        assert any(c['type'] == 'rgb' for c in result['colors']), "RGB цвет не найден"
        assert any(c['type'] == 'hsl' for c in result['colors']), "HSL цвет не найден"

        assert 'Roboto' in result['fonts'], "Шрифт Roboto не найден"
        assert 'Montserrat' in result['fonts'], "Шрифт Montserrat не найден"
        assert 'CustomFont' in result['fonts'], "Шрифт CustomFont (@font-face) не найден"

        assert (tmp / 'ui_palette.json').exists(), "ui_palette.json не создан"
        assert result['stats']['css_files'] == 1
        assert result['stats']['html_files'] == 1

    print(
        f"[PASS] DesignAnalyzer — "
        f"{result['stats']['total_colors']} цветов, "
        f"{result['stats']['total_fonts']} шрифтов"
    )
    return True


def test_anti_detect_session():
    # Profile validation and fallback
    s = AntiDetectSession()
    s.configure(profile='chrome_windows', rotate_ua=False)
    assert s.profile == 'chrome_windows'
    assert s._rotate_ua is False

    s.configure(profile='nonexistent_browser')
    assert s.profile == 'chrome_windows', "Несуществующий профиль должен откатываться на chrome_windows"

    # Header generation
    s.configure(profile='firefox_windows', rotate_ua=False)
    h = s._headers()
    assert 'User-Agent' in h
    assert 'Firefox' in h['User-Agent']
    assert 'Accept-Encoding' in h

    # UA rotation produces variety across profiles
    s.configure(profile='chrome_windows', rotate_ua=True)
    agents = {s._headers()['User-Agent'] for _ in range(30)}
    assert len(agents) > 1, "UA-ротация должна давать несколько разных User-Agent значений"

    # Retry / backoff config
    s.configure(retry_count=5, base_delay=0.5)
    assert s._retry_count == 5
    assert s._base_delay == 0.5

    # Each configure() resets the cookie jar
    jar1 = id(s._cookie_jar)
    s.configure()
    jar2 = id(s._cookie_jar)
    assert jar1 != jar2, "configure() должен сбрасывать cookie jar"

    print("[PASS] AntiDetectSession — профили, UA-ротация, конфигурация OK")
    return True


def test_frontend_cloner_pipeline():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Page with only data: URIs — no network calls needed
        html = (
            '<!DOCTYPE html><html><head>'
            '<link rel="stylesheet" href="data:text/css,body{}">'
            '<title>Offline Test</title></head>'
            '<body>'
            '<img src="data:image/png;base64,abc123" alt="ok">'
            '<script src="data:text/javascript,void 0"></script>'
            '</body></html>'
        )
        (tmp / 'index.html').write_text(html, encoding='utf-8')
        (tmp / 'site_map.json').write_text(
            json.dumps([{'url': 'https://example.com/', 'file': str(tmp / 'index.html')}]),
            encoding='utf-8',
        )

        cloner = FrontendCloner()
        cloner.configure(tmpdir)
        result = cloner.clone()

        assert result['status'] == 'Success', f"Ожидали Success, получили: {result['status']}"
        assert result['pages_processed'] == 1
        assert result['assets_downloaded'] == 0, "data: URI не должен скачиваться"

        out = (tmp / 'index.html').read_text(encoding='utf-8')
        assert 'data:image/png;base64,abc123' in out, "data: URI должен остаться нетронутым"
        assert 'data:text/css' in out

        # Asset classification helper
        assert cloner._subdir('https://x.com/s.css')   == 'css'
        assert cloner._subdir('https://x.com/a.js')    == 'js'
        assert cloner._subdir('https://x.com/i.png')   == 'img'
        assert cloner._subdir('https://x.com/f.woff2') == 'fonts'
        assert cloner._subdir('https://x.com/f.svg')   == 'img'
        assert cloner._is_asset('https://x.com/s.css')  is True
        assert cloner._is_asset('https://x.com/p.html') is False

        # Unique local filename generation
        n1 = cloner._local_name('https://cdn.example.com/path/style.css')
        n2 = cloner._local_name('https://other.example.com/path/style.css')
        assert n1.endswith('.css') and n2.endswith('.css')
        assert n1 != n2, "Разные URL должны давать разные имена файлов"

    print("[PASS] FrontendCloner — пайплайн локализации, классификация ассетов OK")
    return True


if __name__ == "__main__":
    tests = [
        test_api_key_patterns,
        test_cloudflare_detection,
        test_rate_limit_detection,
        test_file_compression,
        test_url_normalization,
        test_waf_detection,
        test_design_analyzer,
        test_anti_detect_session,
        test_frontend_cloner_pipeline,
    ]

    passed = failed = 0
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1

    print(f"\nРезультат: {passed} прошло, {failed} провалено")
    sys.exit(0 if failed == 0 else 1)
