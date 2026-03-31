# Notice: j41-jailbox → Relay/Dispatcher Team

**From:** j41-jailbox (SDK team)
**Date:** 2026-03-30
**Re:** workspace → jailbox rename — coordination notes

---

## 1. SovGuard API — No Breaking Change

SovGuard's `POST /v1/report` endpoint now accepts both `workspace_uid` and `jailbox_uid` in the request body. j41-jailbox is now sending `jailbox_uid`. Teams can switch at their own pace — no coordination window needed.

---

## 2. What Changed in j41-jailbox (SDK-Internal)

These changes are live in j41-jailbox as of commit `8853f6d`:

| Component | Before | After |
|-----------|--------|-------|
| Socket.IO namespace | `/workspace` | `/jailbox` |
| Event prefix | `workspace:*` | `jailbox:*` |
| Docker mount path | `/workspace` | `/jailbox` |
| Config types | `WorkspaceConfig`, `WorkspaceMode` | `JailboxConfig`, `JailboxMode` |
| Report field | `workspace_uid` | `jailbox_uid` |
| UI strings | "Workspace active/paused" | "Jailbox active/paused" |

None of this touches the SovGuard API surface. It's all between j41-jailbox and the relay.

---

## 3. Action Required: Relay/Dispatcher

The relay **must** update to match the new names before j41-jailbox clients on this version can connect:

- **Namespace:** Listen on `/jailbox` instead of `/workspace`
- **Events (buyer → relay):**
  - `jailbox:pre_scan_done` (was `workspace:pre_scan_done`)
  - `jailbox:pause` / `jailbox:resume` / `jailbox:abort` / `jailbox:accept`
  - `jailbox:ping`
- **Events (relay → buyer):**
  - `jailbox:status_changed` (was `workspace:status_changed`)
  - `jailbox:agent_done` (was `workspace:agent_done`)
  - `jailbox:agent_disconnected` (was `workspace:agent_disconnected`)
- **Events (relay → agent/dispatcher):**
  - `jailbox:exclusions` (was `workspace:exclusions`)

**Suggested rollout:** Support both `/workspace` and `/jailbox` namespaces on the relay during transition, then deprecate `/workspace` once all SDK clients have updated.

**Priority:** High — current j41-jailbox builds will fail to connect until the relay supports `/jailbox`.

---

## 4. Action Required: SDK/Dispatcher (j41-sovagent-sdk)

The following changes are needed in the agent-side SDK:

| File | Change |
|------|--------|
| `src/workspace/client.ts:134` | `/v1/workspace/:jobId/connect-token` → `/v1/jailbox/:jobId/connect-token` |
| `src/client/index.ts:1226` | `/v1/workspace/:jobId` → `/v1/jailbox/:jobId` |
| Socket.IO connection | Namespace `/workspace` → `/jailbox` |
| All event listeners | `workspace:*` → `jailbox:*` |

Same pattern as the buyer-side rename — find-and-replace `workspace` → `jailbox` in namespace, event names, and API paths. Internal types (e.g. `WorkspaceClient`) can be renamed at the SDK team's discretion.
