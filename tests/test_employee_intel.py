"""Tests for Employee Intelligence (core/employee_intel.py, roadmap #13 OSINT).

Extraction, format inference and roster building are pure; fetches are injected
so nothing hits the network.
"""

from core import employee_intel as ee, scan_diff


def _ldjson(*persons):
    import json
    body = json.dumps(list(persons))
    return f'<script type="application/ld+json">{body}</script>'


# ── name / format helpers (pure) ──────────────────────────────────────────────

def test_split_name():
    assert ee._split_name('Jane Smith') == ('jane', 'smith')
    assert ee._split_name('John A. Doe') == ('john', 'doe')   # drops middle
    assert ee._split_name('Renée Müller') == ('rene', 'mller')  # ascii-only
    assert ee._split_name('') == ('', '')


def test_match_and_infer_format():
    assert ee._match_format('jane', 'smith', 'jane.smith') == '{first}.{last}'
    assert ee._match_format('jane', 'smith', 'jsmith') == '{f}{last}'
    # Most common scheme across pairs wins.
    pairs = [('jane', 'smith', 'jane.smith'),
             ('bob', 'lee', 'bob.lee'),
             ('amy', 'ng', 'angng')]          # noise / no clean match
    assert ee.infer_format(pairs) == '{first}.{last}'


def test_generate_email_only_with_format():
    assert ee.generate_email('Jane Smith', '{f}{last}', 'x.com') == 'jsmith@x.com'
    assert ee.generate_email('Jane Smith', None, 'x.com') is None   # no guessing
    assert ee.generate_email('Cher', '{first}.{last}', 'x.com') is None  # no last


# ── extract_people (pure) ─────────────────────────────────────────────────────

def test_extract_people_from_jsonld():
    text = _ldjson(
        {'@type': 'Person', 'name': 'Jane Smith', 'jobTitle': 'CTO',
         'email': 'jane.smith@x.com',
         'sameAs': ['https://linkedin.com/in/janesmith']},
        {'@type': 'Organization', 'name': 'Acme'})          # ignored
    people = ee.extract_people(text, 'x.com')
    assert len(people) == 1
    assert people[0]['name'] == 'Jane Smith' and people[0]['title'] == 'CTO'
    assert people[0]['social'] == ['https://linkedin.com/in/janesmith']


def test_extract_people_from_mailto_skips_roles_and_external():
    text = ('<a href="mailto:bob.lee@x.com">Bob</a> '
            '<a href="mailto:info@x.com">info</a> '          # role → skipped
            '<a href="mailto:carol.fox@other.com">Carol</a>')  # off-domain
    people = ee.extract_people(text, 'x.com')
    assert [p['name'] for p in people] == ['Bob Lee']
    assert people[0]['email'] == 'bob.lee@x.com'


def test_extract_walks_nested_graph():
    text = _ldjson({'@graph': [
        {'@type': 'Person', 'name': 'Amy Ng', 'jobTitle': 'CEO'}]})
    people = ee.extract_people(text, 'x.com')
    assert people and people[0]['name'] == 'Amy Ng'


# ── build_roster (pure) ───────────────────────────────────────────────────────

def test_roster_infers_format_and_fills_addresses():
    people = [
        {'name': 'Jane Smith', 'title': 'CTO', 'email': 'jane.smith@x.com',
         'social': []},
        {'name': 'Bob Lee', 'title': 'Engineer', 'email': '', 'social': []},
    ]
    r = ee.build_roster(people, 'x.com')
    assert r['format'] == '{first}.{last}' and r['total'] == 2
    by = {p['name']: p for p in r['people']}
    assert by['Jane Smith']['email_source'] == 'found'
    assert by['Bob Lee']['email'] == 'bob.lee@x.com'
    assert by['Bob Lee']['email_source'] == 'inferred'


def test_roster_no_format_means_no_invented_emails():
    people = [{'name': 'Bob Lee', 'title': '', 'email': '', 'social': []}]
    r = ee.build_roster(people, 'x.com')
    assert r['format'] is None
    assert r['people'][0]['email'] == '' and r['people'][0]['email_source'] == ''
    assert r['with_email'] == 0


def test_roster_merges_duplicate_person():
    people = [
        {'name': 'Jane Smith', 'title': 'CTO', 'email': '', 'social': []},
        {'name': 'Jane Smith', 'title': '', 'email': 'jane.smith@x.com',
         'social': ['https://x.com/jane']},
    ]
    r = ee.build_roster(people, 'x.com')
    assert r['total'] == 1
    p = r['people'][0]
    assert p['title'] == 'CTO' and p['email'] == 'jane.smith@x.com'
    assert p['social'] == ['https://x.com/jane']


# ── discover (injected fetch) ─────────────────────────────────────────────────

def test_discover_harvests_team_pages():
    pages = {
        'https://x.com/team': _ldjson(
            {'@type': 'Person', 'name': 'Jane Smith', 'jobTitle': 'CTO',
             'email': 'jane.smith@x.com'}),
        'https://x.com/about': '<a href="mailto:bob.lee@x.com">Bob</a>',
    }
    out = ee.discover('https://x.com', fetch=lambda u: pages.get(u, ''))
    assert out['status'] == 'Success' and out['domain'] == 'x.com'
    assert out['total'] == 2 and out['format'] == '{first}.{last}'
    assert set(out['sources']) == {'/team', '/about'}


def test_discover_no_employees():
    out = ee.discover('https://x.com', fetch=lambda u: 'nothing here')
    assert out['status'] == 'No employees' and out['total'] == 0


def test_discover_strips_www():
    text = _ldjson({'@type': 'Person', 'name': 'Jane Smith',
                    'email': 'jane.smith@x.com'})
    out = ee.discover('https://www.x.com', fetch=lambda u: text)
    assert out['domain'] == 'x.com'


# ── render_html (offline) ─────────────────────────────────────────────────────

def test_render_html_offline():
    out = ee.discover('https://x.com', fetch=lambda u: _ldjson(
        {'@type': 'Person', 'name': 'Jane Smith', 'jobTitle': 'CTO',
         'email': 'jane.smith@x.com'}))
    page = ee.render_html(out)
    assert '<script' not in page and 'cdn' not in page.lower()
    assert 'Jane Smith' in page and 'jane.smith@x.com' in page and 'CTO' in page


def test_render_html_no_employees():
    assert 'не найдены' in ee.render_html({'status': 'No employees'})


# ── integration: scan_diff employees section ──────────────────────────────────

def _report_with_people(names):
    return {'phases': {'employees': {'status': 'Success', 'data': {
        'people': [{'name': n, 'title': ''} for n in names]}}}}


def test_scan_diff_reports_new_employee():
    a = _report_with_people(['Jane Smith'])
    b = _report_with_people(['Jane Smith', 'Bob Lee'])
    d = scan_diff.diff(a, b)
    assert d['sections']['employees']['added'] == ['Bob Lee']
