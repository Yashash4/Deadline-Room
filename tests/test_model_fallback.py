"""test_model_fallback.py -- the cross-family failover walk (E5.7 part 1).

floor.model_fallback.call_with_failover walks an ordered (provider, model) chain,
moving to the next entry on a TERMINAL error and serving from the first entry that
works. It mirrors floor.retry one level up: retry recovers a TRANSIENT failure on
the same model; failover steps over a DEAD model to the next family. The
served_by / fell_back_from record is OUT-OF-LOG.
"""

import pytest

from floor.model_fallback import (
    FailoverExhausted, FailoverResult, call_with_failover)


def _chain():
    return [("featherless", "deepseek"), ("featherless", "minimax"),
            ("featherless", "qwen")]


def test_primary_serves_no_fallback():
    """When the first model works, it serves and nothing is fallen back from."""
    seen = []

    def fn(provider, model):
        seen.append((provider, model))
        return f"draft by {model}"

    result = call_with_failover(_chain(), fn, classify_terminal=lambda e: True)
    assert isinstance(result, FailoverResult)
    assert result.value == "draft by deepseek"
    assert result.served_by == ("featherless", "deepseek")
    assert result.fell_back_from == []
    assert result.did_fail_over is False
    assert seen == [("featherless", "deepseek")]  # later models never tried


def test_fails_over_to_next_model_on_terminal_error():
    """A terminal error on the primary advances to the next model, which serves."""
    def fn(provider, model):
        if model == "deepseek":
            raise RuntimeError("model 404")
        return f"draft by {model}"

    result = call_with_failover(_chain(), fn, classify_terminal=lambda e: True)
    assert result.value == "draft by minimax"
    assert result.served_by == ("featherless", "minimax")
    assert result.fell_back_from == [("featherless", "deepseek")]
    assert result.did_fail_over is True


def test_walks_whole_chain_then_serves_from_last():
    """Two dead models fall through to the third, which serves."""
    def fn(provider, model):
        if model in ("deepseek", "minimax"):
            raise RuntimeError(f"{model} down")
        return "draft by qwen"

    result = call_with_failover(_chain(), fn, classify_terminal=lambda e: True)
    assert result.served_by == ("featherless", "qwen")
    assert result.fell_back_from == [("featherless", "deepseek"),
                                     ("featherless", "minimax")]
    assert [a.model for a in result.attempts] == ["deepseek", "minimax", "qwen"]
    assert result.attempts[-1].error == ""  # the serving entry has no error


def test_whole_chain_down_raises_with_all_errors():
    """When every model fails terminally, FailoverExhausted carries every error and
    nothing is swallowed."""
    def fn(provider, model):
        raise RuntimeError(f"{model} terminal")

    with pytest.raises(FailoverExhausted) as exc:
        call_with_failover(_chain(), fn, classify_terminal=lambda e: True)
    assert len(exc.value.attempts) == 3
    msg = str(exc.value)
    assert "deepseek" in msg and "minimax" in msg and "qwen" in msg


def test_non_failover_error_is_reraised_immediately():
    """An error the classifier deems NOT failover-worthy (a real bug) surfaces at
    once, without trying the next model: a fallback never masks a bug."""
    def fn(provider, model):
        raise KeyError("a programming bug")

    with pytest.raises(KeyError):
        call_with_failover(_chain(), fn, classify_terminal=lambda e: False)


def test_empty_chain_is_a_programming_error():
    with pytest.raises(ValueError):
        call_with_failover([], lambda p, m: "x", classify_terminal=lambda e: True)


def test_result_as_dict_is_out_of_log_record():
    def fn(provider, model):
        if model == "deepseek":
            raise RuntimeError("down")
        return "ok"

    result = call_with_failover(_chain(), fn, classify_terminal=lambda e: True)
    d = result.as_dict()
    assert d["served_by_model"] == "minimax"
    assert d["did_fail_over"] is True
    assert d["fell_back_from"] == [{"provider": "featherless", "model": "deepseek"}]
    # the record carries no [CLAIMS] / gate field: it is purely descriptive
    assert set(d) == {"served_by_provider", "served_by_model", "fell_back_from",
                      "did_fail_over", "attempts"}
