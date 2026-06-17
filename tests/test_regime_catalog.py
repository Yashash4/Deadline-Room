"""The declarative regime catalog (floor/regimes.yaml) and its loader (PART A).

The six live REGULATOR regimes are produced FROM the catalog, alongside the
affected-party / GDPR Art 34 communication-to-data-subject obligation (a
non-regulator, post-release obligation, E3.4). These tests pin the catalog shape
and the refactor's load-bearing equivalence: the recruit targets and the startup
clocks produced from data are EXACTLY the prior constants, which is why the demo
run stays byte-identical.
"""

from floor import regimes
from floor.recruit import NYDFS_TARGET, UK_ICO_TARGET, target_from_spec


def test_catalog_has_the_six_live_regulator_regimes():
    specs = regimes.load_catalog()
    keys = {s.key for s in specs}
    # The six regulator regimes are all present.
    assert {"nis2_early", "nis2_full", "dora", "sec", "uk_ico", "nydfs"} <= keys
    # Plus the affected-party / Art 34 communication-to-data-subject obligation: a
    # non-regulator, post-release obligation, not a startup or recruit clock.
    assert "data_subject" in keys
    ds = regimes.by_key(specs)["data_subject"]
    assert ds.is_post_release
    assert not ds.is_startup and not ds.is_recruit
    assert ds.high_risk is not None


def test_startup_and_recruit_partition():
    specs = regimes.load_catalog()
    startup = {s.branch for s in regimes.startup_regimes(specs)}
    recruit = {s.branch for s in regimes.recruit_regimes(specs)}
    # NIS2 early + full, DORA, SEC start at floor open; UK + NYDFS at recruit.
    assert startup == {"nis2-early", "nis2", "dora", "sec"}
    assert recruit == {"uk", "nydfs"}


def test_sec_regime_is_four_business_days_from_determination():
    spec = regimes.by_key(regimes.load_catalog())["sec"]
    assert spec.clock.length == 4
    assert spec.clock.unit == regimes.UNIT_BUSINESS_DAYS
    assert spec.clock.business_days is True
    # The catalog names a registry calendar id (warden.clocks.HOLIDAY_CALENDARS)
    # the business-day count actually consults; the SEC count skips US federal
    # holidays. The deterministic display zone is America/New_York.
    assert spec.clock.holiday_calendar == "US_FEDERAL"
    assert spec.clock.display_timezone == "America/New_York"
    assert spec.trigger_event == "materiality determination"
    assert spec.start_anchor == regimes.ANCHOR_MATERIALITY_DETERMINATION


def test_nis2_and_dora_anchor_at_t0():
    by = regimes.by_key(regimes.load_catalog())
    for key in ("nis2_early", "nis2_full", "dora"):
        assert by[key].start_anchor == regimes.ANCHOR_INCIDENT_T0
        assert by[key].clock.unit == regimes.UNIT_HOURS


def test_recruit_targets_match_the_prior_constants():
    # The byte-identical guard for the recruit targets: building them from the
    # catalog yields exactly the values the floor used as hardcoded constants.
    by = regimes.by_key(regimes.load_catalog())
    uk = target_from_spec(by["uk_ico"])
    nydfs = target_from_spec(by["nydfs"])

    assert UK_ICO_TARGET == uk
    assert NYDFS_TARGET == nydfs

    assert uk.jurisdiction == "UK"
    assert uk.branch == "uk"
    assert uk.regime == "UK ICO"
    assert uk.name_tokens == ("uk", "ico")
    assert uk.clock_name == "UK ICO / GDPR personal-data breach (72h)"
    assert uk.clock_hours == 72
    assert uk.trigger_event == "becoming aware"

    assert nydfs.jurisdiction == "NY"
    assert nydfs.branch == "nydfs"
    assert nydfs.regime == "NYDFS 23 NYCRR 500"
    assert nydfs.name_tokens == ("nydfs",)
    assert nydfs.clock_name == "NYDFS 23 NYCRR 500.17(a)(1) (72h from determination)"
    assert nydfs.clock_hours == 72
    assert nydfs.trigger_event == "determination (recruit moment)"


def test_missing_regimes_list_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("something: else\n", encoding="utf-8")
    try:
        regimes.load_catalog(bad)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a catalog with no regimes list")
