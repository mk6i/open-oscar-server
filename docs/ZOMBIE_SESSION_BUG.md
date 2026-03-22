# Zombie Session Bug — Full Context for Fix

## The Bug

There is a race condition in the session management system that creates permanent "zombie" sessions, locking users out until server restart.

**Reproduction script:** `scripts/repro_zombie_session.py` — login, abrupt socket close, two parallel re-logins for the same user. Run with `python3 scripts/repro_zombie_session.py` while the server is running.

## Root Cause

When a user logs in, `Signon` (in `server/toc/cmd_client.go`) does two things in sequence:

1. Calls `RegisterBOSSession` → `AddSession`, which creates a session and stores it in the session map. `AddSession` holds a per-user lock (`lockUser`) and releases it via `defer unlockUser` when it returns.
2. After `RegisterBOSSession` returns, calls `instance.Session().OnSessionClose(func() { ... })` to register the cleanup callback that calls `Signout` → `RemoveSession`.

The problem: `NewSession()` (in `state/session.go`) initializes `onSessCloseFn` to a **no-op** (`func() {}`). Between step 1 (session stored in map, user lock released) and step 2 (real callback registered), a concurrent login for the same user can call `AddSession`, find the new session, evict it via `CloseSession` → `closeOnly`, and run the **no-op** `onSessCloseFn`. Since `RemoveSession` is never called, the `removed` channel is never closed, and the session slot stays in the store forever. Every subsequent login waits 5 seconds on `<-active.removed`, times out, and fails.

The per-user lock makes this easy to trigger: if login C is blocked on `lockUser` while login B's `AddSession` runs, C acquires the lock the instant B releases it — before B can call `OnSessionClose`.

## Key Code Paths

**Session store** — `state/session_manager.go`:
- `AddSession` (line ~180): acquires per-user lock, finds active session, calls `CloseSession` to evict it, waits on `<-active.removed` (5s timeout from `RegisterBOSSession`), then calls `newSession`.
- `newSession` (line ~218): creates `NewSession()`, stores `sessionSlot{session, removed: make(chan bool)}` in map.
- `RemoveSession` (line ~247): deletes from map, `close(rec.removed)`.

**Session lifecycle** — `state/session.go`:
- `NewSession()` (line ~91): sets `onSessCloseFn: func() {}` (the default no-op).
- `OnSessionClose` (line ~584): replaces `onSessCloseFn` with the real cleanup function.
- `CloseSession` (line ~569): calls `closeOnly` on all instances.
- `closeOnly` (line ~1121): sets `closed=true`, calls `RemoveInstance`, if `InstanceCount()==0` runs `onSessCloseFn`.
- `CloseInstance` (line ~1086): same pattern but also runs `onInstanceCloseFn` if instances remain.

**Auth layer** — `foodgroup/auth.go`:
- `RegisterBOSSession` (line ~111): creates 5-second timeout context, calls `AddSession`, does post-setup.

**TOC Signon** — `server/toc/cmd_client.go` (line ~2302):
- Calls `RegisterBOSSession` (creates session, releases user lock).
- Then `RunOnce` (RegisterBuddyList, recalcWarning — I/O work).
- Then `instance.OnClose(...)`.
- Then `instance.Session().OnSessionClose(...)` — **too late if session was already evicted**.

**OSCAR server** — `server/oscar/server.go` (line ~250): same pattern, same bug.

**WebAPI** — `server/webapi/handlers/session.go` (line ~213): calls `AddSession` but **never** registers `OnSessionClose`.

## What Needs to Happen

The `onSessCloseFn` (which calls `Signout` → `RemoveSession` → `close(removed)`) must be registered **atomically** with session creation — before the session becomes visible in the store or before the per-user lock is released. There are 6 affected call sites across TOC, OSCAR, and WebAPI servers.

**Option B (reorder code) was tried and failed** — even moving `OnSessionClose` to immediately after `RegisterBOSSession` doesn't help because the per-user lock release in `AddSession` lets a waiting goroutine evict the session before the caller can register the callback. The git working tree has this failed attempt in `server/toc/cmd_client.go` — revert it first with `git checkout -- server/toc/cmd_client.go`.

**Viable approaches:**
- **Option A:** Pass the cleanup callback as a parameter to `AddSession`/`newSession` so it's set on the `Session` before being stored in the map. Requires changing the API of `AddSession`, `RegisterBOSSession`, `RegisterChatSession`, and all callers/mocks.
- **Option C:** In `AddSession`, when the 5-second timeout fires, forcibly delete the zombie session slot from the store (`delete(s.store, ...)` + `close(rec.removed)`) and retry creating a new session instead of returning an error. Self-healing, no API changes.

## Testing

After applying a fix: rebuild (`go build -o open_oscar_server ./cmd/server`), start the server, run `python3 scripts/repro_zombie_session.py` at least 5 times in a row. Every run should report "Bug NOT triggered" — never "ZOMBIE SESSION CONFIRMED". Also run `go test -race ./...` to ensure no regressions.
