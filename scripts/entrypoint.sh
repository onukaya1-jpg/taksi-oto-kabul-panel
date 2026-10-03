#!/bin/sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GameStore Auth Server — Container Entrypoint
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. Seed license keys from data/licenses_seed.json (baked into image)
# 2. Seed license keys from SEED_LICENSE_KEYS env var
# 3. Start uvicorn with Render.com $PORT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -e

PORT="${PORT:-8443}"
WORKERS="${WORKERS:-2}"

echo "=== GameStore Auth Server ==="
echo "PORT=$PORT  WORKERS=$WORKERS  ENV=$ENVIRONMENT"

# ── Seed from JSON file (always runs — idempotent) ──
SEED_FILE="/app/data/licenses_seed.json"
if [ -f "$SEED_FILE" ]; then
    echo ">>> Seeding from $SEED_FILE ..."
    python -c "
import asyncio, json, sys
sys.path.insert(0, '/app')
from app.database import init_db, get_session_factory
from app.models import License
from sqlalchemy import select
from datetime import datetime, timezone, timedelta

async def seed_from_file():
    await init_db()
    factory = get_session_factory()
    with open('$SEED_FILE', 'r') as f:
        data = json.load(f)
    licenses = data.get('licenses', [])
    created = 0
    for item in licenses:
        key = item['key'].strip().upper()
        plan = item.get('plan', 'basic')
        days = item.get('days', 365)
        max_dev = item.get('max_devices', 1)
        notes = item.get('notes', 'seeded-from-file')
        async with factory() as db:
            exists = await db.execute(select(License).where(License.license_key == key))
            if exists.scalar_one_or_none():
                print(f'  [exists] {key}')
                continue
            now = datetime.now(timezone.utc)
            lic = License(
                license_key=key,
                plan=plan,
                is_active=True,
                is_revoked=False,
                created_at=now,
                expires_at=now + timedelta(days=days),
                max_devices=max_dev,
                notes=notes,
            )
            db.add(lic)
            await db.commit()
            print(f'  [created] {key} ({plan}, {days}d, max_dev={max_dev})')
            created += 1
    print(f'  File seed done: {created} created, {len(licenses)-created} already existed')

asyncio.run(seed_from_file())
" || echo "WARNING: File seed script failed, continuing..."
fi

# Seed license keys if SEED_LICENSE_KEYS is set
if [ -n "$SEED_LICENSE_KEYS" ]; then
    echo ">>> Seeding license keys..."
    python -c "
import asyncio, os, sys
sys.path.insert(0, '/app')
from app.database import init_db, get_session_factory
from app.models import License
from sqlalchemy import select
from datetime import datetime, timezone, timedelta

async def seed():
    await init_db()
    factory = get_session_factory()
    keys_str = os.environ.get('SEED_LICENSE_KEYS', '')
    if not keys_str:
        return
    for entry in keys_str.split(','):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(':')
        key = parts[0].strip()
        plan = parts[1].strip() if len(parts) > 1 else 'premium'
        days = int(parts[2].strip()) if len(parts) > 2 else 365
        max_dev = int(parts[3].strip()) if len(parts) > 3 else 3
        
        async with factory() as db:
            exists = await db.execute(select(License).where(License.license_key == key))
            if exists.scalar_one_or_none():
                print(f'  [exists] {key}')
                continue
            now = datetime.now(timezone.utc)
            lic = License(
                license_key=key,
                plan=plan,
                is_active=True,
                is_revoked=False,
                created_at=now,
                expires_at=now + timedelta(days=days),
                max_devices=max_dev,
                notes='seeded-on-startup',
            )
            db.add(lic)
            await db.commit()
            print(f'  [created] {key} ({plan}, {days}d, max_dev={max_dev})')

asyncio.run(seed())
" || echo "WARNING: Seed script failed, continuing..."
    echo ">>> Seed complete."
fi

echo ">>> Starting uvicorn on port $PORT..."
exec uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers "$WORKERS" \
    --no-access-log
