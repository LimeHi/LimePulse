import os

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

# Path to the sing-box binary. The provided Dockerfile installs it to
# /usr/local/bin/sing-box
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")

# URL used to check whether a proxied connection actually works
TEST_URL = os.environ.get("TEST_URL", "https://www.gstatic.com/generate_204")

# Per-config connection timeout, seconds
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "8"))

# How many configs are tested in parallel within one job
TEST_CONCURRENCY = int(os.environ.get("TEST_CONCURRENCY", "15"))

# How many subscription jobs run at the same time across all users.
# Keep this at 1-2 on small hosts - each job already tests many configs
# in parallel internally.
JOB_CONCURRENCY = int(os.environ.get("JOB_CONCURRENCY", "1"))

# Hard cap on configs accepted from a single subscription
MAX_CONFIGS = int(os.environ.get("MAX_CONFIGS", "400"))

# Local port range used to spin up throwaway sing-box instances
PORT_RANGE_START = int(os.environ.get("PORT_RANGE_START", "20000"))
PORT_RANGE_END = int(os.environ.get("PORT_RANGE_END", "29999"))

# Where temporary sing-box config files / working dirs are written
WORK_DIR = os.environ.get("WORK_DIR", "/tmp/singbox_jobs")
