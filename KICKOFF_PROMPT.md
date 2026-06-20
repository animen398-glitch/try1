# Стартовый промпт для Claude Code

> Скопируй блок ниже как первое сообщение в Claude Code (терминал), запущенный
> из корня проекта. `CLAUDE.md` подтянется автоматически — этот промпт лишь
> запускает первый шаг.

---

```
Контекст и правила — в CLAUDE.md и ROADMAP_ASM_2.0.md. Прочитай оба перед началом.

Мы открываем Epic: ASM Platform 2.0. Цель — превратить проект из Security
Analyzer в платформу ASM/CSM, сместив акцент с поиска данных на управление ими.

ШАГ 1 — НЕ ПИШИ КОД. Сначала выполни аудит текущей архитектуры под этот эпик:

1. Подтверди фактическую раскладку core/ , gui/ , utils/ , remote/ , plugins/
   и как сейчас устроены: CollectionRunner, risk-движок, scan_diff, project.py
   (ProjectStore), endpoint_index, secret_scanner, metadata.json. Где именно
   рождаются "находки" сегодня и в каком виде они доходят до report.json.

2. Оцени готовность к фундаменту Findings: есть ли уже что-то, что можно
   переиспользовать для идентичности находки (нормализация эндпоинтов,
   секрет-правила, scan_diff). Не дублировать существующее.

ШАГ 2 — Предложи план для F1 (Findings Management) из роадмапа, конкретно:
- схему fingerprint находки (детерминированную, стабильную между сканами,
  без хранения секретов в открытом виде) — это главное решение, обоснуй;
- модель данных SQLite (findings + finding_events), idempotent-миграцию,
  не ломающую существующие БД;
- точки интеграции: где вызвать sync(project, scan_id, findings), как findings
  влияют на risk score, как читает Dashboard и web-консоль;
- правила жизненного цикла, включая липкость IGNORED/FALSE_POSITIVE и
  авто-FIXED только при успешной фазе;
- список затрагиваемых файлов и риски обратной совместимости;
- какие тесты (offline/headless) это покроют.

ОГРАНИЧЕНИЯ (из CLAUDE.md):
- Работать только локально. Никаких git push/commit/clone/pull/fetch, PR,
  изменения remote/origin, релизов — версионирую я сам.
- Без техдолга, костылей и дублирования. Переиспользовать существующие
  компоненты. Не ломать backward compatibility (Projects/, metadata.json,
  report.json, контракты _start_task/_run_async).
- Все новые пути — через PathManager (frozen-aware, .exe).
- Если данных не хватает — остановись и спроси, не выдумывай.

Покажи план для ШАГ 2 и ОСТАНОВИСЬ для утверждения. Код начнём только после
моего "ок, реализуй T1.x".

После каждой задачи давай отчёт: Что сделано / Какие файлы изменены / Почему
так / Риски / Что дальше.
```

---

## Как этим пользоваться дальше (рабочий цикл)

1. Запусти Claude Code из корня проекта → вставь промпт выше.
2. Получи аудит + план F1 → проверь/поправь (или прогони через GPT как ревьюера).
3. Утверди одну задачу: `ок, реализуй T1.2 (findings_store + миграция)`.
4. После реализации проверь отчёт, прогони `pytest`, проверь сборку окна.
5. Переходи к следующей задаче. Не запускай несколько Epic'ов параллельно.

### Полезные короткие команды-реплики в сессии

- `Покажи план, не пиши код` — когда нужен только дизайн.
- `Реализуй T2.3, минимальный диф, потом отчёт` — точечная задача.
- `Прогони pytest и покажи только упавшие` — проверка.
- `Это меняет контракт X — стоп, объясни влияние на обратную совместимость`.
- `Недостаточно данных по Y — задай уточняющие вопросы вместо догадок`.
## Current Handoff Prompt - Epic 14

Use this block when continuing in Claude Code from the repository root.

```
Context and rules are in AGENTS.md, ROADMAP_ASM_2.0.md, PROJECT_STATUS.txt, and
PROJECT_REPORT.md. Read them before coding.

Current focus: Epic 14 - Scope & Evidence Foundation.

Goal: improve trust in collected data, safe active operations, and evidence
traceability. Do NOT add new scanners and do NOT work on GUI/design unless a
later explicit task says so. Prefer core/ logic with thin CLI/reporting wrappers.

Completed Epic 14 items:
- E14.1 Scope Guard v1
- E14.2 Evidence Manifest v1
- E14.3 Evidence Integrity Hook / evidence_cli.py
- E14.4 Finding Evidence Persistence v1

Approved next tasks, in order:
1. E14.5 Scope CLI / Project Scope Management
   Thin local CLI over Project.get_scope()/set_scope(): show/set/clear,
   allowed/wildcard/denied domains, active_scan_enabled, passive_only, rate_limit.
   No GUI, no scanner changes, no network.

2. E14.6 Evidence Refs Coverage Expansion
   Expand evidence refs for existing finding producers only when existing
   artifacts prove the finding. Keep refs flat: artifact_id/path/phase.

3. E14.7 Report / Export Traceability
   Surface evidence refs in backend report/export outputs. No raw secrets.

4. E14.8 Scope Guard Coverage Audit
   Add regression tests that active operations cannot bypass Scope Guard.

5. E14.9 Evidence Integrity Integration With Monitor/Export
   Add non-blocking integrity warnings/status for monitor/export consumers.

6. E14.10 Roadmap / Status Cleanup
   Keep ROADMAP_ASM_2.0.md, PROJECT_STATUS.txt, PROJECT_REPORT.md,
   KICKOFF_PROMPT.md aligned.

Process:
- Before coding any task, show a short plan: files, contracts preserved, backward
  compatibility risk.
- Implement minimal scoped diff.
- Add offline tests.
- Run ruff, targeted pytest, full pytest.
- Update PROJECT_STATUS.txt.
- Make a local commit. Do not push/fetch/pull/clone.

Start with E14.5 unless the user explicitly chooses another item.
```

---
