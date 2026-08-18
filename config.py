import os
from dotenv import load_dotenv
load_dotenv()

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")

# Path to the sing-box binary. The provided Dockerfile installs it to
# /usr/local/bin/sing-box
SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")

# Единственный шаг проверки: запрос к IP-эхо сервису через прокси.
# Ответ должен быть JSON с реальным IP в поле "ip" — это сложно
# подделать блок-страницей DPI, в отличие от простого статус-кода.
#
# ФИКС: раньше это были ДВА разных шага (отдельная "пустая" connectivity
# проба на generate_204 + отдельно ipify) и TEST_URL_PRIMARY был URL-ом
# generate_204-типа (без JSON), нигде фактически не использовавшимся.
# Теперь один унифицированный список IP-эхо провайдеров, TEST_URL_PRIMARY
# реально пробуется первым, а при неудаче — короткий перебор запасных,
# без ipify-специфичных рейт-лимитов на один-единственный сервис.
TEST_URL_PRIMARY = os.environ.get("TEST_URL_PRIMARY", "https://api.ipify.org?format=json")
TEST_URL_VERIFY = os.environ.get("TEST_URL_VERIFY", "https://api.ipify.org?format=json")
TEST_URL_VERIFY_FALLBACKS = [
    "https://api64.ipify.org?format=json",
    "https://ifconfig.co/json",
    "https://ipinfo.io/json",
]

# Overall per-request timeout, seconds (первая попытка verify получает
# этот бюджет целиком, повторные — короче, см. singbox_runner._verify)
# Приоритет теперь качество проверки, а не скорость — бюджет увеличен.
TEST_TIMEOUT = float(os.environ.get("TEST_TIMEOUT", "20"))

# TCP connect timeout, seconds
TEST_CONNECT_TIMEOUT = float(os.environ.get("TEST_CONNECT_TIMEOUT", "10"))

# A real round trip through a remote exit node essentially never comes
# back faster than this; anything under it is treated as a fake/local
# response rather than a working proxy.
# Снижено с 15 до 5 мс — 15 мс иногда отсекало близкие ноды
MIN_PLAUSIBLE_LATENCY_MS = float(os.environ.get("MIN_PLAUSIBLE_LATENCY_MS", "5"))

# Сколько РАЗНЫХ IP-эхо провайдеров должны независимо подтвердить, что
# конфиг реально проксирует трафик, прежде чем он считается рабочим.
# Раньше хватало одного успешного ответа — этого достаточно, чтобы
# отсечь мёртвые серверы, но не достаточно, чтобы отсечь DPI/block-page,
# которая иногда отдаёт правдоподобный JSON на один конкретный домен.
REQUIRED_VERIFY_MATCHES = int(os.environ.get("REQUIRED_VERIFY_MATCHES", "2"))

# Пауза перед повторной проверкой на стабильность, сек. После того как
# конфиг прошёл первичную верификацию, ждём этот интервал и делаем ещё
# один запрос через тот же прокси — отсеивает ноды, которые "живут"
# долю секунды и затем рвут соединение (типично для перегруженных или
# банящихся по IP серверов). 0 — отключить.
STABILITY_RECHECK_DELAY = float(os.environ.get("STABILITY_RECHECK_DELAY", "3"))

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
