"""Offline tests for the Context-Aware Wordlist Manager (Roadmap E5)."""

from core.wordlist_manager import (
    budget_from_roe,
    categories_for,
    plan_wordlist,
    select_paths,
    technologies_from_report,
)


def _active_roe(rate="1/s"):
    return {
        "profile": "client_safe",
        "allowed_domains": ["example.com"],
        "active_scan_enabled": True,
        "passive_only": False,
        "rate_limit": rate,
    }


# --- category / path selection -----------------------------------------------

def test_baseline_categories_always_present():
    cats = categories_for([])
    assert cats[:3] == ["generic", "config", "vcs"]


def test_technology_unlocks_its_category():
    cats = categories_for([{"name": "WordPress"}])
    assert "wordpress" in cats


def test_tech_names_tolerate_str_and_dict():
    assert "php" in categories_for(["PHP"])
    assert "django" in categories_for([{"name": "Django"}])


def test_select_paths_includes_baseline_and_tech():
    paths = select_paths([{"name": "WordPress"}])
    assert "/robots.txt" in paths          # generic baseline
    assert "/.git/HEAD" in paths           # vcs baseline
    assert "/wp-login.php" in paths        # wordpress-specific


def test_select_paths_deduped_and_deterministic():
    a = select_paths(["laravel"])   # laravel adds /.env which is also in config
    assert a.count("/.env") == 1
    assert a == select_paths(["laravel"])


def test_unknown_tech_yields_only_baseline():
    paths = select_paths([{"name": "SomeUnknownStack"}])
    assert "/robots.txt" in paths
    assert "/wp-login.php" not in paths


def test_extra_categories_can_add_api():
    paths = select_paths([], extra_categories=["api"])
    assert "/graphql" in paths


def test_technologies_from_report():
    report = {"phases": {"recon": {"data": {
        "technologies": [{"name": "nginx"}, {"name": "PHP"}],
        "cms": ["WordPress"],
    }}}}
    names = technologies_from_report(report)
    assert "php" in names and "wordpress" in names


# --- budget ------------------------------------------------------------------

def test_budget_from_rate():
    assert budget_from_roe({"rate_limit": "2/s"}, window_s=60) == 120


def test_budget_default_without_rate():
    assert budget_from_roe({"rate_limit": None}) == 50


def test_budget_is_capped():
    assert budget_from_roe({"rate_limit": "1000/s"}, window_s=60) == 500


# --- plan_wordlist (ROE-aware) -----------------------------------------------

def test_plan_authorized_for_active_roe():
    plan = plan_wordlist([{"name": "WordPress"}], _active_roe())
    assert plan["authorized"] is True
    assert plan["candidates"]
    assert "/wp-login.php" in plan["candidates"]
    assert plan["budget"] == 60  # 1/s * 60s


def test_plan_refuses_passive_only():
    roe = {"profile": "client_safe", "passive_only": True,
           "active_scan_enabled": False}
    plan = plan_wordlist([{"name": "WordPress"}], roe)
    assert plan["authorized"] is False
    assert plan["candidates"] == []
    assert "passive" in plan["reason"]
    # It still reports what *would* be available for transparency.
    assert plan["total_available"] > 0


def test_plan_truncates_to_budget():
    # A tiny budget (1/min ≈ 1 candidate over the window) truncates the list.
    plan = plan_wordlist([{"name": "WordPress"}], _active_roe(rate="1/min"))
    assert plan["truncated"] is True
    assert len(plan["candidates"]) < plan["total_available"]
    assert len(plan["candidates"]) == plan["budget"]


def test_plan_respects_explicit_max_candidates():
    plan = plan_wordlist([{"name": "WordPress"}], _active_roe(), max_candidates=3)
    assert len(plan["candidates"]) == 3
    assert plan["truncated"] is True


def test_plan_none_roe_is_passive_by_default():
    # DEFAULT_ROE is passive_only=True → unauthorized without an explicit ROE.
    plan = plan_wordlist([{"name": "WordPress"}], None)
    assert plan["authorized"] is False


def test_plan_candidates_never_exceed_budget():
    plan = plan_wordlist(["wordpress", "php", "django"], _active_roe(rate="5/s"))
    assert len(plan["candidates"]) <= plan["budget"]
