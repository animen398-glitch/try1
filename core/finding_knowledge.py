"""core/finding_knowledge.py
Rule-level knowledge for findings — description / impact / remediation (Epic F-O).

A finding answers *what* was found; a security team also needs *why it matters*
and *how to fix it* (the Nuclei/DefectDojo "finding object"). That text is
knowledge about the **rule**, almost static per ``(category, rule_id)`` — not data
of a single occurrence. So it is modelled as a pure, offline **catalog resolved on
read** (derive-on-read, like ``findings_sla``), NOT a per-row schema change:

  * fingerprint identity is untouched (this text never enters the fingerprint);
  * the findings DB schema is unchanged (nothing stored per row by this module);
  * scanners are untouched — but any text a producer *does* supply (e.g. a nuclei
    template's ``info.remediation``) wins and is carried in ``evidence``.

Resolution order per field (``describe``): explicit ``evidence`` value → a rule
specific (matched by keyword in rule_id/title) → the per-category default → a
generic fallback. Pure and stdlib-only (architectural invariants I1/I5).
"""

from typing import Dict, List, Optional

# The three knowledge fields, in display order. Also the keys ``describe``
# returns and the columns the CSV/web surfaces read.
FIELDS = ('description', 'impact', 'remediation')


def _k(description: str, impact: str, remediation: str) -> Dict[str, str]:
    return {'description': description, 'impact': impact,
            'remediation': remediation}


# Per-category defaults. Categories mirror finding_fingerprint.CATEGORIES (+ the
# adapter's 'transport'). Text is concise, technically accurate, UI-language (ru).
_CATEGORY: Dict[str, Dict[str, str]] = {
    'header': _k(
        'Отсутствует или ослаблен HTTP-заголовок безопасности '
        '(CSP / HSTS / X-Frame-Options и т.п.).',
        'Повышает риск XSS, clickjacking, MITM и утечки реферера.',
        'Добавьте недостающие заголовки безопасности на уровне сервера/прокси и '
        'задайте строгие значения (CSP без unsafe-inline, HSTS с max-age и '
        'includeSubDomains, X-Frame-Options: DENY).'),
    'cookie': _k(
        'Cookie выставлен без флагов безопасности (Secure / HttpOnly / SameSite).',
        'Возможен перехват сессии по HTTP, доступ к cookie из JS (XSS) и CSRF.',
        'Установите Secure, HttpOnly и SameSite=Lax/Strict для всех сессионных '
        'cookie.'),
    'secret': _k(
        'В клиентском коде или ответах обнаружен секрет (API-ключ, токен).',
        'Утечка ключа ведёт к несанкционированному доступу к API/сервисам и '
        'возможным финансовым расходам.',
        'Немедленно отзовите и ротируйте ключ; перенесите секрет на бэкенд; '
        'ограничьте его scope и привязку (referrer/IP).'),
    'sourcemap': _k(
        'Доступна source map, раскрывающая исходный код фронтенда.',
        'Раскрывает внутреннюю логику, пути и потенциально комментарии/секреты.',
        'Не публикуйте .map-файлы в проде (или закройте доступ) и уберите '
        'ссылки sourceMappingURL из бандлов.'),
    'graphql': _k(
        'Доступен GraphQL-эндпоинт; возможно включена интроспекция схемы.',
        'Интроспекция раскрывает полную схему API и упрощает перечисление и атаки.',
        'Отключите интроспекцию в проде, включите ограничение глубины/сложности '
        'запросов и обязательную авторизацию.'),
    'dns': _k(
        'Проблема конфигурации DNS или почтовой аутентификации (SPF/DKIM/DMARC).',
        'Облегчает спуфинг домена и фишинг от его имени.',
        'Настройте корректные SPF, DKIM и DMARC; удалите устаревшие/висячие '
        'записи.'),
    'dependency': _k(
        'Используется зависимость с известной уязвимостью (CVE).',
        'Уязвимая библиотека может эксплуатироваться (RCE/XSS/DoS — по CVE).',
        'Обновите библиотеку до исправленной версии; если нельзя — примените '
        'митигации или замену.'),
    'vuln': _k(
        'Обнаружена потенциальная уязвимость веб-приложения.',
        'В зависимости от типа — компрометация данных, сессий или инфраструктуры.',
        'Подтвердите и устраните по типу уязвимости; примените валидацию '
        'ввода/вывода и актуальные патчи.'),
    'transport': _k(
        'Небезопасный транспорт: обычный HTTP или слабый TLS.',
        'Трафик может быть перехвачен или изменён (MITM).',
        'Принудительно используйте HTTPS, включите HSTS и отключите устаревшие '
        'протоколы/шифры.'),
    'tech': _k(
        'Раскрыты технология/стек или их версии.',
        'Облегчает таргетирование известных уязвимостей этого стека.',
        'Скрывайте версии и баннеры; поддерживайте компоненты в актуальном '
        'состоянии.'),
    'endpoint': _k(
        'Обнаружен чувствительный или неожиданный эндпоинт/путь.',
        'Может раскрывать админ-функции, отладку или внутренние данные.',
        'Ограничьте доступ (аутентификация/allowlist) и уберите отладочные и '
        'служебные пути из прода.'),
    'takeover': _k(
        'Субдомен указывает (CNAME) на неактивный сторонний сервис — возможен '
        'захват субдомена (subdomain takeover).',
        'Злоумышленник может занять сервис и размещать контент на вашем '
        'субдомене: фишинг, кража cookie/сессий, обход CORS/CSP.',
        'Удалите висячую DNS-запись или верните контроль над сервисом '
        '(зарегистрируйте/привяжите ресурс).'),
    'iac': _k(
        'Небезопасная конфигурация инфраструктуры-как-кода / контейнера '
        '(Dockerfile, compose, Kubernetes, CloudFormation, Terraform).',
        'Слабая настройка (root-контейнер, привилегии, открытый 0.0.0.0/0, '
        'публичный бакет) расширяет поверхность атаки и blast radius.',
        'Примените принцип наименьших привилегий: непривилегированный пользователь, '
        'фиксированные теги образов, ограниченные CIDR/ACL, приватные бакеты.'),
}

_GENERIC = _k(
    'Находка безопасности, требующая проверки.',
    'Потенциально влияет на безопасность приложения.',
    'Проверьте находку и устраните согласно лучшим практикам безопасности.')

# Rule specifics: (keyword matched in "<rule_id> <title>" lowercased) → field
# overrides layered on top of the category default. First match wins per field.
_RULE_SPECIFICS = (
    ('hsts', {'remediation': 'Включите HSTS: '
              'Strict-Transport-Security: max-age=31536000; includeSubDomains; '
              'preload.'}),
    ('content-security-policy', {'remediation': 'Задайте строгую CSP без '
     "unsafe-inline/unsafe-eval; используйте nonce/hash для скриптов."}),
    ('csp', {'remediation': 'Задайте строгую Content-Security-Policy без '
     "unsafe-inline/unsafe-eval."}),
    ('x-frame-options', {'impact': 'Допускает clickjacking (встраивание в iframe).',
     'remediation': 'Установите X-Frame-Options: DENY или CSP frame-ancestors '
     "'none'."}),
    ('introspection', {'impact': 'Полная схема GraphQL доступна без авторизации.',
     'remediation': 'Отключите интроспекцию в проде.'}),
    ('plain http', {'remediation': 'Перенаправляйте весь трафик на HTTPS и '
     'включите HSTS.'}),
)


def describe(category: str, rule_id: str = '', title: str = '',
             evidence: Optional[Dict] = None) -> Dict[str, str]:
    """Resolve ``{description, impact, remediation}`` for a finding (pure).

    Per field: an explicit value in ``evidence`` wins, else a rule specific
    (keyword in rule_id/title), else the per-category default, else generic.
    """
    cat = str(category or '').strip().lower()
    base = dict(_CATEGORY.get(cat, _GENERIC))

    hay = f'{str(rule_id or "").lower()} {str(title or "").lower()}'
    for keyword, overrides in _RULE_SPECIFICS:
        if keyword in hay:
            for field, text in overrides.items():
                base[field] = text

    evidence = evidence if isinstance(evidence, dict) else {}
    for field in FIELDS:
        val = evidence.get(field)
        if isinstance(val, str) and val.strip():
            base[field] = val.strip()
    return base


def annotate(findings: List[Dict]) -> List[Dict]:
    """Add ``description``/``impact``/``remediation`` to each finding row in place.

    Mirrors ``findings_sla.annotate`` — a read-time enrichment used by the CSV
    export and the web surface. Returns the same list for chaining."""
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        info = describe(f.get('category', ''), f.get('rule_id', ''),
                        f.get('title', ''), f.get('evidence'))
        f.update(info)
    return findings
