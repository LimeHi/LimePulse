import os
from dotenv import load_dotenv
load_dotenv()

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

# Path to the sing-box binary. The provided Dockerfile installs it to
# /usr/local/bin/sing-box
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")

# Step 1: connectivity probe URLs — see singbox_runner._GENERATE_204_URLS
# (primary used for backward compat env override; runner always tries all fallbacks)
TEST_URL_PRIMARY = os.environ.get("TEST_URL_PRIMARY", "https://cp.cloudflare.com/generate_204")

# Step 2: content-verified probe. Response must be JSON with a real IP in
# an "ip" field - this is much harder for a block page to fake than a
# bare status code.
TEST_URL_VERIFY = os.environ.get("TEST_URL_VERIFY", "https://api.ipify.org?format=json")

# Overall per-request timeout, seconds
# Увеличено с 8 до 12: три последовательных запроса (204 + ipify + speed),
# медленным нодам 8 сек не хватало
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "12"))

# TCP connect timeout, seconds
TEST_CONNECT_TIMEOUT = float(os.environ.get("TEST_CONNECT_TIMEOUT", "6"))

# A real round trip through a remote exit node essentially never comes
# back faster than this; anything under it is treated as a fake/local
# response rather than a working proxy.
# Снижено с 15 до 5 мс — 15 мс иногда отсекало близкие ноды
MIN_PLAUSIBLE_LATENCY_MS = float(os.environ.get("MIN_PLAUSIBLE_LATENCY_MS", "5"))

# Speed test
SPEEDTEST_URL = os.environ.get("SPEEDTEST_URL", "https://speed.cloudflare.com/__down?bytes=4000000")

# Hard cap on how long the speed test is allowed to run per config
SPEEDTEST_MAX_DURATION = float(os.environ.get("SPEEDTEST_MAX_DURATION", "6"))

# A config is marked "fast" (⚡️) if it clears EITHER of these bars
MIN_FAST_SPEED_MBPS = float(os.environ.get("MIN_FAST_SPEED_MBPS", "10"))
MAX_FAST_PING_MS = float(os.environ.get("MAX_FAST_PING_MS", "80"))

# How many configs are tested in parallel within one job
TEST_CONCURRENCY = int(os.environ.get("TEST_CONCURRENCY", "5"))

# How many subscription jobs run at the same time across all users.
JOB_CONCURRENCY = int(os.environ.get("JOB_CONCURRENCY", "1"))

# Hard cap on configs accepted from a single subscription
MAX_CONFIGS = int(os.environ.get("MAX_CONFIGS", "400"))

# Local port range used to spin up throwaway sing-box instances
PORT_RANGE_START = int(os.environ.get("PORT_RANGE_START", "20000"))
PORT_RANGE_END = int(os.environ.get("PORT_RANGE_END", "29999"))

# Where temporary sing-box config files / working dirs are written
WORK_DIR = os.environ.get("WORK_DIR", "/tmp/singbox_jobs")

TELEGRAM_PROXY_HOST = os.getenv("TELEGRAM_PROXY_HOST", "")
