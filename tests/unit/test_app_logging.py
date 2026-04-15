from __future__ import annotations

from attackcastle.app import _target_input_summary


def test_target_input_summary_keeps_start_log_single_line() -> None:
    summary = _target_input_summary(
        "\n".join(
            [
                "20.211.105.66",
                "40.126.227.192",
                "20.92.248.205",
                "4.197.9.78",
                "4.197.9.63",
                "www.hbfdental.com.au",
            ]
        ),
        max_examples=3,
    )

    assert summary["count"] == 6
    assert summary["targets"] == [
        "20.211.105.66",
        "40.126.227.192",
        "20.92.248.205",
        "4.197.9.78",
        "4.197.9.63",
        "www.hbfdental.com.au",
    ]
    assert "\n" not in summary["summary"]
    assert summary["summary"] == "6 target(s): 20.211.105.66, 40.126.227.192, 20.92.248.205, +3 more"
