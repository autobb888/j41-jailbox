# Request: j41-connect → Junction41 Backend/Relay

**From:** j41-connect (SDK/Dispatcher team)
**Date:** 2026-03-26
**Re:** Relay changes needed for j41-connect v0.2.0 features

---

## 1. Keepalive Ping Support

**What j41-connect now does:** Emits `workspace:ping` every 30 seconds on the `/workspace` namespace to prevent idle timeout disconnects.

**What we need from the relay:**
- The relay should either explicitly handle `workspace:ping` (reset idle timer, optionally respond with `workspace:pong`), OR confirm that any Socket.IO traffic on the namespace already resets the idle timer.
- If neither is true, sessions will still die after ~10 minutes of agent thinking time (the original bug).

**Priority:** High — this is the root cause of the "Invalid workspace UID" disconnects that have been killing sessions at the 10-12 minute mark.

---

## 2. SovGuard False Positive Report Endpoint

**What j41-connect now does:** When a buyer overrides a SovGuard block or types `report`, j41-connect queues a false positive report to `~/.j41/sovguard-reports.jsonl`. The report contains: file path, content hash (sha256), score, mime type, workspace UID, timestamp, verdict.

**What we need from SovGuard:**
- `POST /v1/report` endpoint
- Accepts: `{ file_path, content_hash, score, mime_type, workspace_uid, timestamp, verdict }` (same shape as what we queue)
- Auth: `X-API-Key` header (same as scan endpoint)
- Purpose: feed false positive data back for model improvement

**When j41-connect will use it:** On session start, `SovGuardClient.flushReports()` sends queued reports and purges entries older than 30 days. Currently this is a stub that only purges.

**Priority:** Medium — queuing works, flushing is stubbed.

---

## 3. Enhanced Scan Response Fields

**What j41-connect now does:** When SovGuard flags a file, we show the buyer a generic message: `SovGuard flagged as unsafe (score: 0.85)`. If the API response includes `reason` or `category` fields, we use those instead for a more specific message.

**What we need from SovGuard:**
- Add optional `reason` and `category` fields to the `/v1/scan/file/content` response
- Example: `{ "safe": false, "score": 0.85, "category": "hardcoded_credential", "reason": "AWS access key detected" }`
- If not feasible, the current generic fallback works fine.

**Priority:** Low — nice UX improvement but not blocking.

---

## 4. Reconnect Token Flow

**What j41-connect now does:** Socket.IO reconnects automatically on transport disconnect (5 attempts, 2s delay). After reconnect, the feed shows "Reconnected to relay."

**What we need confirmed from the relay:**
- Does a Socket.IO reconnect preserve the workspace session? Or does the buyer need to re-authenticate with a reconnect token?
- If re-auth is needed, does the relay emit a `workspace:reconnect_token` event that j41-connect should listen for and store?
- The `--resume` flag already supports reconnect tokens, but the automatic reconnect flow doesn't use it yet.

**Priority:** Medium — transport reconnects work via Socket.IO, but unclear if the session state survives.

---

## 5. Health Check Endpoint

**What j41-connect now does:** `j41-connect doctor` checks if the relay is reachable by hitting `GET /health` on `https://api.junction41.io`.

**What we need from the relay:**
- Confirm there is a `/health` endpoint (currently returns 404 in testing)
- If not, add one — simple 200 OK response is sufficient

**Priority:** Low — doctor command works around it with a warning.
