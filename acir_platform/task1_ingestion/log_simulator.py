# =============================================================================
# log_simulator.py — Generates realistic synthetic security logs
# Produces both normal traffic and injected attack patterns:
#   - Brute-force logins
#   - Late-night database scraping
#   - Lateral movement (SSH hopping)
#   - Port scanning
#   - Data exfiltration bursts
# =============================================================================

import random
import uuid
from datetime import datetime, timedelta
from faker import Faker
from models import RawLog

fake = Faker("en_GB")
Faker.seed(42)
random.seed(42)

# ── Internal IP pools ─────────────────────────────────────────────────────────
INTERNAL_IPS  = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(30)]
DB_SERVER_IPS = ["10.0.1.10", "10.0.1.11", "10.0.1.12"]
APP_SERVER_IPS = ["10.0.2.20", "10.0.2.21"]
EXTERNAL_IPS  = [fake.ipv4_public() for _ in range(20)]

USERNAMES = [fake.user_name() for _ in range(50)]

EVENT_TYPES_NORMAL = [
    "login_success", "logout", "file_read", "api_call",
    "db_query", "email_sent", "vpn_connect", "vpn_disconnect",
    "password_change", "mfa_success",
]

ATTACK_PATTERNS = [
    "brute_force",
    "db_scraping",
    "lateral_movement",
    "port_scan",
    "data_exfiltration",
]


def _random_time(base: datetime, spread_hours: int = 8) -> datetime:
    """Returns a random datetime within ±spread_hours of base."""
    delta = timedelta(seconds=random.randint(0, spread_hours * 3600))
    return base + delta


def _business_hours_time(base: datetime) -> datetime:
    """Returns a datetime within business hours (08:00–18:00)."""
    hour   = random.randint(8, 17)
    minute = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=random.randint(0, 59))


def _offhours_time(base: datetime) -> datetime:
    """Returns a datetime outside business hours (00:00–06:00 or 22:00–23:59)."""
    hour = random.choice(list(range(0, 6)) + list(range(22, 24)))
    return base.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))


# ── Normal log generators ─────────────────────────────────────────────────────

def _gen_normal_log(base_time: datetime) -> RawLog:
    user = random.choice(USERNAMES)
    src  = random.choice(INTERNAL_IPS)
    evt  = random.choice(EVENT_TYPES_NORMAL)
    t    = _business_hours_time(base_time)

    payloads = {
        "login_success":   f"User {user} logged in from {src} using MFA.",
        "logout":          f"User {user} session ended. Duration: {random.randint(5,480)}min.",
        "file_read":       f"User {user} accessed /data/reports/Q{random.randint(1,4)}_2025.pdf.",
        "api_call":        f"User {user} called /api/v2/accounts/{fake.bban()} — 200 OK.",
        "db_query":        f"User {user} executed SELECT on accounts table. Rows: {random.randint(1,50)}.",
        "email_sent":      f"User {user} sent email to {fake.email()}. Subject: Meeting Follow-up.",
        "vpn_connect":     f"User {user} established VPN from {fake.ipv4_public()}.",
        "vpn_disconnect":  f"User {user} VPN session terminated.",
        "password_change": f"User {user} changed password. Policy: compliant.",
        "mfa_success":     f"User {user} MFA token verified. Device: mobile.",
    }

    return RawLog(
        timestamp=t,
        source_ip=src,
        dest_ip=random.choice(APP_SERVER_IPS + DB_SERVER_IPS),
        event_type=evt,
        username=user,
        payload=payloads.get(evt, f"Event {evt} by {user}"),
        severity="INFO",
        source=random.choice(["SIEM", "EDR", "NETWORK"]),
    )


# ── Attack pattern generators ─────────────────────────────────────────────────

def _gen_brute_force(base_time: datetime) -> list[RawLog]:
    """Rapid repeated login failures from one external IP."""
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_user = random.choice(USERNAMES)
    logs = []
    t = _offhours_time(base_time)
    for i in range(random.randint(80, 150)):
        t += timedelta(seconds=random.randint(1, 5))
        logs.append(RawLog(
            timestamp=t,
            source_ip=attacker_ip,
            dest_ip=random.choice(APP_SERVER_IPS),
            event_type="login_failed",
            username=target_user,
            payload=f"FAILED LOGIN: user={target_user} from={attacker_ip} "
                    f"attempt={i+1} error=INVALID_PASSWORD account={fake.bban()}",
            severity="WARNING",
            source="SIEM",
        ))
    # Optionally succeed at the end
    if random.random() > 0.5:
        t += timedelta(seconds=2)
        logs.append(RawLog(
            timestamp=t,
            source_ip=attacker_ip,
            dest_ip=random.choice(APP_SERVER_IPS),
            event_type="login_success",
            username=target_user,
            payload=f"LOGIN SUCCESS after {len(logs)} failures: user={target_user} "
                    f"from={attacker_ip} card={fake.credit_card_number()}",
            severity="CRITICAL",
            source="SIEM",
        ))
    return logs


def _gen_db_scraping(base_time: datetime) -> list[RawLog]:
    """Burst of DB SELECT queries in the middle of the night."""
    src_ip = random.choice(INTERNAL_IPS)
    user   = random.choice(USERNAMES)
    logs   = []
    t      = _offhours_time(base_time)
    tables = ["customers", "accounts", "transactions", "loans", "credit_scores"]
    for i in range(random.randint(400, 900)):
        t += timedelta(milliseconds=random.randint(50, 300))
        table = random.choice(tables)
        logs.append(RawLog(
            timestamp=t,
            source_ip=src_ip,
            dest_ip=random.choice(DB_SERVER_IPS),
            event_type="db_query",
            username=user,
            payload=f"DB SELECT: user={user} table={table} rows_returned={random.randint(100,5000)} "
                    f"query_id={uuid.uuid4()} nhs={fake.bothify('???######')} "
                    f"phone={fake.phone_number()}",
            severity="WARNING",
            source="SIEM",
        ))
    return logs


def _gen_lateral_movement(base_time: datetime) -> list[RawLog]:
    """SSH connections hopping between multiple internal servers."""
    attacker_ip = random.choice(EXTERNAL_IPS)
    logs = []
    t    = _offhours_time(base_time)
    hops = random.sample(INTERNAL_IPS, k=min(8, len(INTERNAL_IPS)))
    for hop in hops:
        t += timedelta(seconds=random.randint(10, 120))
        logs.append(RawLog(
            timestamp=t,
            source_ip=attacker_ip,
            dest_ip=hop,
            event_type="ssh_connect",
            payload=f"SSH connection: src={attacker_ip} dst={hop} "
                    f"port=22 key_fingerprint={fake.md5()} user=root",
            severity="WARNING",
            source="NETWORK",
        ))
        t += timedelta(seconds=random.randint(5, 30))
        attacker_ip = hop   # pivot from this host
    return logs


def _gen_port_scan(base_time: datetime) -> list[RawLog]:
    """Sequential port probe from a single external IP."""
    attacker_ip = random.choice(EXTERNAL_IPS)
    target_ip   = random.choice(INTERNAL_IPS)
    logs = []
    t    = _offhours_time(base_time)
    for port in random.sample(range(1, 65535), k=random.randint(200, 500)):
        t += timedelta(milliseconds=random.randint(10, 100))
        status = "OPEN" if port in [22, 80, 443, 3306, 5432, 8080] else "CLOSED"
        logs.append(RawLog(
            timestamp=t,
            source_ip=attacker_ip,
            dest_ip=target_ip,
            event_type="port_probe",
            payload=f"PORT_SCAN: src={attacker_ip} dst={target_ip} port={port} status={status}",
            severity="WARNING",
            source="NETWORK",
        ))
    return logs


def _gen_data_exfiltration(base_time: datetime) -> list[RawLog]:
    """Large outbound data transfers to an external IP."""
    src_ip = random.choice(INTERNAL_IPS)
    ext_ip = random.choice(EXTERNAL_IPS)
    user   = random.choice(USERNAMES)
    logs   = []
    t      = _offhours_time(base_time)
    for i in range(random.randint(30, 80)):
        t += timedelta(seconds=random.randint(2, 15))
        size_mb = random.randint(50, 500)
        logs.append(RawLog(
            timestamp=t,
            source_ip=src_ip,
            dest_ip=ext_ip,
            event_type="data_transfer",
            username=user,
            payload=f"OUTBOUND TRANSFER: user={user} src={src_ip} dst={ext_ip} "
                    f"size={size_mb}MB protocol=HTTPS file=/export/dump_{i}.csv "
                    f"iban={fake.iban()} email={fake.email()}",
            severity="CRITICAL",
            source="NETWORK",
        ))
    return logs


# ── Public API ────────────────────────────────────────────────────────────────

def simulate_logs(
    total: int = 500,
    attack_fraction: float = 0.08,
    base_time: datetime | None = None,
) -> list[RawLog]:
    """
    Generate a mixed batch of normal and attack logs.

    Args:
        total:            Total number of log entries to generate.
        attack_fraction:  Fraction of logs that are attack events (0.0–1.0).
        base_time:        Base datetime for log timestamps (default: today at midnight).

    Returns:
        Shuffled list of RawLog objects.
    """
    if base_time is None:
        base_time = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    num_attacks = max(1, int(total * attack_fraction))
    logs: list[RawLog] = []

    # ── Inject attack patterns ────────────────────────────────────────────────
    generators = [
        _gen_brute_force,
        _gen_db_scraping,
        _gen_lateral_movement,
        _gen_port_scan,
        _gen_data_exfiltration,
    ]
    attack_logs: list[RawLog] = []
    while len(attack_logs) < num_attacks:
        gen = random.choice(generators)
        attack_logs.extend(gen(base_time))

    attack_logs = attack_logs[:num_attacks]
    logs.extend(attack_logs)

    # ── Fill remainder with normal logs ───────────────────────────────────────
    num_normal = total - len(logs)
    for _ in range(num_normal):
        logs.append(_gen_normal_log(base_time))

    random.shuffle(logs)
    return logs


if __name__ == "__main__":
    logs = simulate_logs(total=100, attack_fraction=0.1)
    attack = [l for l in logs if l.event_type not in EVENT_TYPES_NORMAL]
    print(f"Generated {len(logs)} logs  |  Attack events: {len(attack)}")
    print("\nSample log:")
    print(logs[0].model_dump_json(indent=2))
