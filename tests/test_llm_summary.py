"""LLM narrative (local Ollama) — opt-in, graceful, offline-tested.

The real path needs a running Ollama; these tests stub the single network seam
(_post) and the availability probe, so they exercise the wiring, the prompt
building and — crucially — the graceful degradation, without any network. The
model's free text is never asserted on (it is nondeterministic by nature)."""

from core import llm_summary as llm


def _summary():
    return {
        'risk_level': 'High', 'risk_score': 12, 'risk_100': 48,
        'metrics': {'secrets': 1, 'high': 2, 'medium': 3, 'weak_cookies': 1,
                    'pages': 7, 'risk_100': 48},
        'key_findings': ['Утечки секретов/ключей: 1', 'Высокосерьёзных: 2'],
        'recommendations': ['Отозвать ключи', 'Устранить High'],
    }


# ── build_prompt (pure, deterministic) ──────────────────────────────────────

def test_build_prompt_is_deterministic_and_grounded():
    s = _summary()
    p1 = llm.build_prompt(s)
    p2 = llm.build_prompt(s)
    assert p1 == p2                                  # same input → same prompt
    # The verdict and metrics are passed verbatim; the model is told not to change them.
    assert 'High (48/100)' in p1
    assert 'НЕ меняй вердикт' in p1
    assert 'секретов=1' in p1 and 'High=2' in p1
    assert 'Утечки секретов/ключей: 1' in p1
    assert 'Отозвать ключи' in p1


def test_build_prompt_tolerates_missing_fields():
    p = llm.build_prompt({})                          # no metrics/findings/recs
    assert 'Вердикт риска' in p
    assert 'секретов=0' in p


# ── availability probe ──────────────────────────────────────────────────────

def test_available_false_when_probe_raises(monkeypatch):
    def boom(*a, **k):
        raise OSError('connection refused')
    monkeypatch.setattr(llm.urllib.request, 'urlopen', boom)
    assert llm.available() is False


def test_available_true_on_2xx(monkeypatch):
    class FakeResp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
    monkeypatch.setattr(llm.urllib.request, 'urlopen',
                        lambda *a, **k: FakeResp())
    assert llm.available() is True


# ── generate_narrative (graceful, network stubbed) ──────────────────────────

def test_generate_unavailable_when_no_ollama(monkeypatch):
    monkeypatch.setattr(llm, 'available', lambda *a, **k: False)
    out = llm.generate_narrative(_summary())
    assert out['status'] == 'Unavailable'
    assert out['narrative'] is None


def test_generate_success_with_stubbed_post(monkeypatch):
    monkeypatch.setattr(llm, 'available', lambda *a, **k: True)
    captured = {}

    def fake_post(url, payload, timeout):
        captured['url'] = url
        captured['payload'] = payload
        return {'response': '  Сайт демонстрирует высокий риск из-за утечки.  '}

    monkeypatch.setattr(llm, '_post', fake_post)
    out = llm.generate_narrative(_summary(), model='llama3')
    assert out['status'] == 'Success'
    assert out['narrative'] == 'Сайт демонстрирует высокий риск из-за утечки.'
    assert out['model'] == 'llama3'
    # It posts to the local generate endpoint with our model + non-streaming.
    assert captured['url'].endswith('/api/generate')
    assert captured['payload']['model'] == 'llama3'
    assert captured['payload']['stream'] is False


def test_generate_error_on_empty_response(monkeypatch):
    monkeypatch.setattr(llm, 'available', lambda *a, **k: True)
    monkeypatch.setattr(llm, '_post', lambda *a, **k: {'response': '   '})
    out = llm.generate_narrative(_summary())
    assert out['status'] == 'Error'
    assert out['narrative'] is None


def test_generate_never_raises_on_post_failure(monkeypatch):
    monkeypatch.setattr(llm, 'available', lambda *a, **k: True)

    def boom(*a, **k):
        raise RuntimeError('model crashed')
    monkeypatch.setattr(llm, '_post', boom)
    out = llm.generate_narrative(_summary())          # must not raise
    assert out['status'] == 'Error'
    assert 'model crashed' in out['error']


# ── executive summary render: narrative section ─────────────────────────────

def test_exec_render_shows_narrative_when_present():
    from core.executive_summary import render_html
    s = _summary()
    s['narrative'] = 'Цель раскрывает ключ <secret> и имеет 2 High-замечания.'
    s['narrative_model'] = 'llama3'
    html = render_html(s)
    assert 'AI-резюме' in html
    assert 'локальный Ollama · llama3' in html
    assert 'детерминированный' in html               # makes authority explicit
    assert '&lt;secret&gt;' in html                   # narrative is escaped


def test_exec_render_omits_narrative_when_absent():
    from core.executive_summary import render_html
    html = render_html(_summary())
    assert 'AI-резюме' not in html                    # unchanged without Ollama


# ── collection integration (network stubbed) ───────────────────────────────

def test_collection_attaches_narrative_without_touching_verdict(monkeypatch):
    from core.collection_runner import CollectionRunner
    monkeypatch.setattr('core.collection_runner.generate_llm_narrative',
                        lambda summary, model, log: {
                            'status': 'Success', 'narrative': 'AI текст.',
                            'model': model})
    r = CollectionRunner(llm=True)
    summary = {'risk_level': 'High', 'risk_100': 48, 'metrics': {'risk_100': 48}}
    r._attach_llm_narrative(summary)
    assert summary['narrative'] == 'AI текст.'
    # The deterministic verdict is left exactly as it was.
    assert summary['risk_level'] == 'High' and summary['risk_100'] == 48


def test_collection_narrative_graceful_when_unavailable(monkeypatch):
    from core.collection_runner import CollectionRunner
    monkeypatch.setattr('core.collection_runner.generate_llm_narrative',
                        lambda summary, model, log: {
                            'status': 'Unavailable', 'narrative': None,
                            'model': model})
    r = CollectionRunner(llm=True)
    summary = {'risk_level': 'Low', 'risk_100': 4}
    r._attach_llm_narrative(summary)                  # must not raise
    assert 'narrative' not in summary                 # nothing added


def test_default_collection_has_llm_off():
    from core.collection_runner import CollectionRunner
    assert CollectionRunner().llm is False


def test_features_has_ollama_delegates(monkeypatch):
    from core import features
    monkeypatch.setattr('core.llm_summary.available', lambda *a, **k: True)
    assert features.has_ollama() is True
    monkeypatch.setattr('core.llm_summary.available', lambda *a, **k: False)
    assert features.has_ollama() is False
