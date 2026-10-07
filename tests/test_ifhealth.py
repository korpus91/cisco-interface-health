import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import ifhealth  # noqa: E402

SAMPLE = (HERE / "sample_show_interfaces.txt").read_text()


def issues_for(name):
    intf = next(i for i in ifhealth.parse(SAMPLE) if i.name == name)
    return {f.issue: f for f in ifhealth.assess(intf)}


def test_parses_all_interfaces():
    names = [i.name for i in ifhealth.parse(SAMPLE)]
    assert names == [
        "GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3",
        "GigabitEthernet1/0/4", "TenGigabitEthernet1/1/1", "Vlan10",
    ]


def test_clean_port_has_no_findings():
    assert issues_for("GigabitEthernet1/0/1") == {}


def test_crc_is_critical_above_rate():
    f = issues_for("GigabitEthernet1/0/2")
    assert f["CRC errors"].severity == "critical"


def test_duplex_mismatch_and_runts():
    f = issues_for("GigabitEthernet1/0/3")
    assert "Duplex mismatch likely" in f
    assert "Runts/giants" in f


def test_err_disabled_and_flapping():
    f = issues_for("GigabitEthernet1/0/4")
    assert f["err-disabled"].severity == "critical"
    assert "Interface resets" in f


def test_low_drop_rate_is_ignored():
    assert issues_for("TenGigabitEthernet1/1/1") == {}


def test_admin_down_svi_is_clean():
    assert issues_for("Vlan10") == {}


def test_cli_exit_code_and_csv(tmp_path):
    out = tmp_path / "f.csv"
    assert ifhealth.main([str(HERE / "sample_show_interfaces.txt"), "--csv", str(out)]) == 1
    assert out.read_text().count("\n") == 6  # header + 5 findings
