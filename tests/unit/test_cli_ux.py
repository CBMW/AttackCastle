from __future__ import annotations

from attackcastle.cli_ux import UXConfig, build_console


def test_build_console_automation_mode_disables_color():
    config = UXConfig(ui_mode="automation", theme="professional", role="operator", no_color=False)
    console = build_console(config, output_format="text")
    assert console.no_color is True


def test_build_console_plain_theme_when_no_color():
    config = UXConfig(ui_mode="operator", theme="contrast", role="operator", no_color=True)
    console = build_console(config, output_format="text")
    assert console.no_color is True
