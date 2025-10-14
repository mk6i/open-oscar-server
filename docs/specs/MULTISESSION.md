# AIM Multisession Support Specification

**Goal:** Implement multisession support for AIM clients

## Functional Requirements

### 1. Concurrent Session Support
Support multiple concurrent sessions for the same screen name when the client supports it.

- Users with multi-connection-capable clients can sign in from multiple locations at once
- Each session maintains its own independent connection state
- Sessions for the same user are tracked together by screen name
- Max concurrent sessions per user is configurable and enforced

### 2. Client Capability Detection
Detect and respect what the client wants during login.

- Multi-connection flag is sent by client in TLV `0x4A` during **SNAC(0x17, 0x02) BUCPLoginRequest**
- Three flag values: 0x0 (legacy/no support), 0x1 (supports multi-connection), 0x3 (supports but wants single session)

### 3. Session Instance Identification
Each session needs a unique instance ID beyond screen name.

- Generate unique instance ID for each connection
- Instance ID distinguishes between multiple concurrent sessions for same user

### 4. Session-Specific vs User-Level Data
Distinguish between data that is per-session vs per-user.

**Per-Session Data (Independent):**
- Client capabilities (file transfer, voice chat, etc.) - each client may support different features
- Client identification string (client name, version)
- Connection state (IP address, connection time)
- Idle time
- Away status
- Session timeout settings
- Typing notifications - originated from specific session

**User-Level Data (Shared across all sessions):**
- Buddy list (feedbag)
- User profile and directory information
- Buddy icon (BART)
- Warning/evil level
- Preferences and settings
- Blocked users list
- Offline messages (delivered once to first available session)

### 5. New Session Handling
Handle new session connections based on client capability.

- Legacy clients (flag 0x0) always disconnect existing sessions
- Single-session clients (flag 0x3) always disconnect existing sessions
- Multi-connection clients (flag 0x1) - new session is added, joininig existing sessions

### 6. Multi-Session Notifications
Tell users when they sign in from additional locations.

- When a 2nd or later session connects, send an automated system message
- Message format: "AOL System Msg: Your AOL screen name (USERNAME) is now signed into AOL(R) Instant Messenger (TM) in N locations. Click here for more information."
- Message goes to ALL active sessions for that user
- Session count in message is accurate
- Only sent for multi-connection capable sessions
- Notifications can be turned on or off via configuration

### 7. Away Messages & Auto-Responses
Handle away status and auto-responses across multiple sessions.

**Away Status Aggregation:**
- User appears "away" to others ONLY if ALL sessions are away
- User appears "active" to others if ANY session is active
- Presence updates to buddies only happen when aggregate status changes
- Each session has its own independent away status
- Away status changes are tracked per-session

**Auto-Response Behavior:**
- Auto-responses are ONLY sent when ALL sessions are away
- When all sessions are away, sender receives auto-responses from all sessions that have an away message set

### 8. Idle Status Aggregation
Calculate aggregate idle status across all sessions for presence.

- If ALL sessions are idle, return the most recent idle time to other users
- If at least ONE session is not idle, don't return an idle time (user appears active)
- Each session tracks its own idle time independently
- Idle status is aggregated similar to away status

### 9. Presence Broadcasting
Broadcast presence changes to buddies only when aggregate online status changes.

- Buddies get "user online" notification when user's FIRST session comes online
- Buddies don't get duplicate "user online" when additional sessions connect
- Buddies get "user offline" notification when user's LAST session goes offline
- Presence updates are based on aggregate session state, not individual sessions

### 10. Intelligent Message Routing
Route incoming instant messages to the right sessions based on their state.

- Messages go to ALL non-away sessions if any exist
- If ALL sessions are away, messages go to ALL sessions (including away ones)
- Don't send to idle/inactive sessions if active sessions exist

### 11. Typing Notifications (ICBM Channel 1)
Handle typing notifications across multiple sessions.

- Typing notifications (`MTN`) are sent FROM the session where user is typing
- Incoming typing notifications go to ALL active non-away sessions

### 12. Offline Message Delivery
Offline messages stored while user is completely offline.

- Offline messages delivered when FIRST session comes online
- Mark messages as delivered so they don't re-deliver to subsequent sessions
- If message delivery fails, retry on next session login
- Clear offline message queue after successful delivery

### 13. Buddy List Synchronization
Sync buddy list changes across all sessions for the same user.

- When one session adds a buddy, all OTHER sessions get the update
- When one session removes a buddy, all OTHER sessions get the update
- When one session modifies a buddy, all OTHER sessions get the update
- The originating session doesn't receive an echo of its own change
- Feedbag sync works for INSERT, UPDATE, and DELETE operations

### 14. User Profile & Directory Information
User profile updates are user-level and should be consistent.

- Each session can submit its own profile information
- Only the oldest (first) session's profile is displayed to other users
- Directory information updates are user-level
- Buddy icons (BART) are user-level - same icon shown from all sessions

### 15. Warning/Evil Levels
Warning levels are user-level, not session-level.

- Warning level is shared across all sessions
- If user is warned, ALL sessions see the increased warning level
- Warning level decreases over time for the user, not per-session
- Warning notifications broadcast to all active sessions

### 16. Client Capabilities Per Session
Each session may have different client capabilities.

- Sessions report their own capabilities (file transfer, games, voice, etc.)
- Show "most capable" feature set in presence
- Direct connection invitations should target specific session with required capability

### 17. Chat Room Sessions
Handle chat room participation with multisession constraints.

- Only ONE session per user can be in a specific chat room at a time
- If a user tries to join a chat room they're already in (from another session), boot the previous session from that chat room
- **Note:** Historical behavior needs verification - may need adjustment based on actual AIM behavior

### 18. Direct Connections & Rendezvous
**TBD** - Behavior for direct connections (file transfer, Direct IM) and rendezvous with multisession needs further specification.

### 19. Global Rate Limiting
Enforce rate limits per user across all their sessions.

- Rate limits are shared across ALL sessions for the same screen name
- Opening multiple sessions doesn't multiply rate limits
- Rate limit state persists across individual session disconnects
- Users can't circumvent rate limits by rapid sign-off/sign-on

### 20. Admin & System Messages
Handle server admin messages and broadcasts.

- System-wide admin messages broadcast to ALL sessions
- Administrative warnings/notices go to all sessions
- Service announcements delivered to all active sessions
- News/MOTD shown once per user, not per session (track delivery)

## Non-Functional Requirements

### API Stability
Maintain the existing `Session.go` API without breaking changes. All modifications to support multisession should be internal to the session manager and not require changes to code that depends on the Session interface.