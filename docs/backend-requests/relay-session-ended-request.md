# Request: j41-jailbox → Junction41 Relay

**From:** j41-jailbox (SDK team)
**Date:** 2026-04-04
**Re:** Emit `jailbox:session_ended` when job closes

---

## Problem

When the buyer submits a review or ends the job on the dashboard, the jailbox CLI has no way of knowing. The terminal stays active showing "Jailbox active" indefinitely. The buyer has to manually Ctrl+C, and even then the Docker container and relay connection stay alive until the cleanup completes.

## What We Need

Emit a `jailbox:session_ended` event on the `/jailbox` namespace when any of these happen:

- Buyer submits a review (job complete)
- Job is closed or cancelled from the dashboard
- Admin terminates the session
- Session times out server-side

### Event Format

```json
{
  "reason": "review_submitted"
}
```

Possible `reason` values (suggested, not enforced):
- `review_submitted` — buyer finished and reviewed
- `job_closed` — job cancelled/closed from dashboard
- `admin_terminated` — admin action
- `session_timeout` — server-side timeout

### What j41-jailbox Does With It

Already implemented in `1f91fce`:

1. Logs: `Session ended by platform: <reason>`
2. Uploads audit log to platform
3. Stops Docker container (removes it)
4. Disconnects from relay
5. Exits cleanly with code 0

### Fallback

If the relay disconnects the socket server-side (without sending the event), j41-jailbox now also handles that — it disables auto-reconnect and exits. But the explicit event is preferred because:
- It gives the buyer a clear message about WHY the session ended
- It allows the audit log to be uploaded before disconnect
- It's cleaner than relying on Socket.IO disconnect reason parsing

**Priority:** High — without this, every session requires manual Ctrl+C to exit.
