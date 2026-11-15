import os
import sys
import tempfile

ROOT = os.environ.get("HELM_ROOT") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.abspath(ROOT))


def temp_config():
    """Point ~/.config/helm-rdp at a fresh temporary folder."""
    d = tempfile.mkdtemp(prefix="helm-test-")
    os.environ["XDG_CONFIG_HOME"] = d
    os.environ["HELM_RDP_CONF"] = os.path.join(d, "none.conf")
    return d
