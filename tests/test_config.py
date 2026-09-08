import importlib
import os

import pytest

from schema import config as config_module


@pytest.fixture
def config_reload():
    """Lets a test change os.environ and re-run config.py's module-level
    validation to see the effect. config.py's constants are only
    evaluated once, at import time, so testing "what if this env var is
    missing/invalid" requires forcing a fresh evaluation — importlib.reload
    re-runs the module's top-level code in place.

    A test that reloads with a bad or missing value can leave the module
    partway through its evaluation (whatever ran before the line that
    raised keeps its new value; everything after keeps its old value).
    To stop that from leaking into later tests, this fixture snapshots
    the full environment up front and restores it — then reloads again —
    once the test is done, regardless of whether it passed or raised.
    """
    original_environ = dict(os.environ)

    def _reload():
        return importlib.reload(config_module)

    yield _reload

    os.environ.clear()
    os.environ.update(original_environ)
    importlib.reload(config_module)


def test_conftest_env_vars_loaded_correctly():
    # Sanity check that conftest.py's env vars actually reached config.py
    # on its first (real, non-reloaded) import.
    assert config_module.TABLE_NAME == os.environ["TABLE_NAME"]
    assert config_module.SNS_TOPIC_ARN == os.environ["SNS_TOPIC_ARN"]
    assert config_module.SES_SENDER == os.environ["SES_SENDER"]
    assert config_module.AWS_REGION == os.environ["AWS_REGION"]


def test_thresholds_default_when_unset():
    assert config_module.CPU_THRESHOLD_PERCENT == 10
    assert config_module.NETWORK_THRESHOLD_BYTES == 5 * 1024 * 1024
    assert config_module.LB_REQUEST_COUNT_THRESHOLD == 1000
    assert config_module.NAT_GW_CONNECTION_THRESHOLD == 7
    assert config_module.DELETION_DELAY_MINUTES == 10050


def test_region_defaults_to_ap_southeast_1_when_unset(config_reload):
    del os.environ["AWS_REGION"]
    config_reload()
    assert config_module.AWS_REGION == "ap-southeast-1"


@pytest.mark.parametrize("required_var", ["TABLE_NAME", "SNS_TOPIC_ARN", "SES_SENDER"])
def test_missing_required_var_raises(config_reload, required_var):
    del os.environ[required_var]
    # Not `pytest.raises(config_module.ConfigError, ...)`: that reads
    # ConfigError off config_module *before* the reload runs, but the
    # reload re-executes `class ConfigError(Exception): ...`, producing a
    # new class object distinct from the one just captured — so an
    # identity-based match would wrongly fail even on a correct raise.
    # Match by name and message instead, both read after the reload.
    with pytest.raises(Exception) as exc_info:
        config_reload()
    assert type(exc_info.value).__name__ == "ConfigError"
    assert required_var in str(exc_info.value)


def test_non_integer_threshold_raises(config_reload):
    os.environ["CPU_THRESHOLD_PERCENT"] = "not-a-number"
    with pytest.raises(Exception) as exc_info:
        config_reload()
    assert type(exc_info.value).__name__ == "ConfigError"
    assert "CPU_THRESHOLD_PERCENT" in str(exc_info.value)


def test_custom_threshold_overrides_default(config_reload):
    os.environ["CPU_THRESHOLD_PERCENT"] = "42"
    config_reload()
    assert config_module.CPU_THRESHOLD_PERCENT == 42
