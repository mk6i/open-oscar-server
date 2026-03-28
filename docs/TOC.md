# TOC Protocol Specification

Version: TOC 1.0 / TOC 2.0

This document is a reference for the TOC (Talk to OSCAR
Client) protocol as implemented by Open OSCAR Server. It covers both TOC 1.0
and TOC 2.0, and contains enough detail to build a fully-functional client
from scratch.

TOC is an ASCII-based protocol layered on top of FLAP (SFLAP) framing over
TCP. It was originally designed by AOL to service the TiK (Tcl/Tk) and TIC
(Java) AIM clients. TOC 2.0 extends the original protocol with server-side
buddy lists, typing notifications, encoded messages, and richer buddy status
information.

---

## Table of Contents

1. [Transport Layer (FLAP)](#1-transport-layer-flap)
2. [Connection & Authentication](#2-connection--authentication)
3. [Client → Server Commands (TOC 1)](#3-client--server-commands-toc-1)
4. [Client → Server Commands (TOC 2)](#4-client--server-commands-toc-2)
5. [Server → Client Messages (TOC 1)](#5-server--client-messages-toc-1)
6. [Server → Client Messages (TOC 2)](#6-server--client-messages-toc-2)
7. [Error Codes](#7-error-codes)
8. [Escaping & Encoding Rules](#8-escaping--encoding-rules)
9. [Capabilities (UUIDs)](#9-capabilities-uuids)
10. [Complete Session Examples](#10-complete-session-examples)

---

## 1. Transport Layer (FLAP)

All TOC communication is wrapped in FLAP frames over a single TCP
connection. The default port is **9898**.

### 1.1 FLAP Header

Every frame begins with a 6-byte binary header in **network byte order**
(big-endian):

| Offset | Size | Field           | Description                            |
|--------|------|-----------------|----------------------------------------|
| 0      | 1    | Marker          | Always `0x2A` (ASCII `*`)              |
| 1      | 1    | Frame Type      | See below                              |
| 2      | 2    | Sequence Number | Monotonically increasing per direction |
| 4      | 2    | Data Length     | Length of the payload that follows     |

The payload immediately follows the header at offset 6.

### 1.2 Frame Types

| Value | Name       | Description                  |
|-------|------------|------------------------------|
| 1     | SIGNON     | Connection initialization    |
| 2     | DATA       | Normal command/response data |
| 3     | ERROR      | Not used by TOC              |
| 4     | SIGNOFF    | Client disconnect            |
| 5     | KEEP_ALIVE | Heartbeat (no payload)       |

### 1.3 SIGNON Frame Payload

**Server → Client** (after the client sends `FLAPON`):

| Offset | Size | Description                        |
|--------|------|------------------------------------|
| 0      | 4    | FLAP version (always `0x00000001`) |

**Client → Server** (response to the server's signon frame):

| Offset | Size | Description                                  |
|--------|------|----------------------------------------------|
| 0      | 4    | FLAP version (`0x00000001`)                  |
| 4      | 2    | TLV tag (`0x0001`)                           |
| 6      | 2    | Screen name length (N)                       |
| 8      | N    | Normalized screen name (NOT null-terminated) |

### 1.4 DATA Frame Payload

- **Client → Server:** The payload is the TOC command as a null-terminated
  ASCII string. The Data Length includes the null terminator.
- **Server → Client:** The payload is the TOC response as an ASCII string.
  It is NOT null-terminated. The Data Length is the exact string length.

### 1.5 Sequence Numbers

Each direction maintains an independent sequence counter starting at an
arbitrary value (usually 0 for clients). The counter increments by 1 for each
frame sent. When it reaches 65535 it wraps to 0.

### 1.6 Maximum Lengths

- **Client → Server:** 2048 bytes maximum per command. Exceeding this drops
  the connection.
- **Server → Client:** 8192 bytes maximum per message.

---

## 2. Connection & Authentication

### 2.1 Connection Handshake

```
Client                              Server
  |                                    |
  |  --- TCP connect (port 9898) --->  |
  |  --- "FLAPON\r\n\r\n" --------->   |
  |  <-- FLAP SIGNON frame ----------  |
  |  --- FLAP SIGNON frame --------->  |
  |  --- toc_signon/toc2_login ----->  |
  |  <-- SIGN_ON --------------------- |
  |  <-- CONFIG/CONFIG2 -------------- |
  |  <-- NICK ------------------------ |
  |  --- toc_add_buddy (optional) ---> |
  |  --- toc_add_permit (optional) --> |
  |  --- toc_init_done --------------> |
  |  <-- UPDATE_BUDDY (for each   ---  |
  |       online buddy)                |
```

Step by step:

1. Open a TCP connection to the server (default port 9898).
2. Send the string `FLAPON\r\n\r\n` (10 bytes).
3. Server responds with a FLAP SIGNON frame (frame type 1) containing the
   4-byte FLAP version.
4. Client sends a FLAP SIGNON frame back containing: the 4-byte FLAP version,
   a TLV with tag `0x0001` holding the normalized screen name.
5. Client sends the login command as a FLAP DATA frame (frame type 2).
6. On success, the server sends `SIGN_ON`, then `CONFIG`/`CONFIG2`, then
   `NICK`. On failure, the server sends an `ERROR` and/or drops the
   connection.
7. Client optionally sends buddy list and permit/deny setup.
8. Client sends `toc_init_done` to go online. This MUST be sent within 30
   seconds of the signon command.

### 2.2 Password Roasting

Passwords are "roasted" before transmission to prevent cleartext on the wire
(this is obfuscation, not encryption).

**Roasting String:** `Tic/Toc`

**Algorithm:**

1. XOR each byte of the password with the corresponding byte of the roasting
   string (cycling through the string).
2. Convert the result to lowercase hexadecimal.
3. Prepend `0x`.

**Example:** The password `password` roasts to `0x2408105c23001130`.

```python
def roast_password(password):
    roast = "Tic/Toc"
    result = []
    for i, ch in enumerate(password):
        xored = ord(ch) ^ ord(roast[i % len(roast)])
        result.append(f"{xored:02x}")
    return "0x" + "".join(result)
```

### 2.3 TOC 1 Signon

```
toc_signon <authorizer_host> <authorizer_port> <screen_name> <roasted_password> <language> <version>
```

| Parameter        | Description                                                                                   |
|------------------|-----------------------------------------------------------------------------------------------|
| authorizer_host  | Auth server hostname (e.g. `login.oscar.aol.com`). Ignored by Open OSCAR Server but required. |
| authorizer_port  | Auth server port (e.g. `5190`). Ignored but required.                                         |
| screen_name      | User screen name                                                                              |
| roasted_password | Password roasted as described above                                                           |
| language         | Language string (e.g. `english`)                                                              |
| version          | Client version string, max 50 characters (e.g. `"TIC:MyClient"`)                              |

**Example:**

```
toc_signon login.oscar.aol.com 5190 toctest1 0x2408105c23001130 english "TIC:MyClient 1.0"
```

On success, the server replies with:

```
SIGN_ON:TOC1.0
CONFIG:<config data>
NICK:<formatted screen name>
```

### 2.4 TOC 2 Signon (toc2_signon)

Same syntax as `toc_signon`. The server replies with `SIGN_ON:TOC2.0` and
`CONFIG2` instead of `CONFIG`. TOC 2 features (server-side buddy list,
`UPDATE_BUDDY2`, `IM_IN2`, etc.) are enabled.

```
toc2_signon login.oscar.aol.com 5190 toctest1 0x2408105c23001130 english "TIC:MyClient 1.0"
```

### 2.5 TOC 2 Login (toc2_login)

Extends `toc2_signon` with additional trailing parameters and enables encoded
message variants (`IM_IN_ENC2`, `CHAT_IN_ENC`).

```
toc2_login <host> <port> <screen_name> <roasted_pw> <language> <version> 160 US "" "" 3 0 30303 -kentucky -utf8 <code>
```

| Parameter                              | Description                                                     |
|----------------------------------------|-----------------------------------------------------------------|
| (first 6)                              | Same as `toc_signon`                                            |
| 160 US "" "" 3 0 30303 -kentucky -utf8 | Fixed parameters (send verbatim)                                |
| code                                   | Login code: `7696 * ascii(screen_name[0]) * ascii(password[0])` |

The version string MUST start with `TIC:` (e.g. `"TIC:MyClient"`).

**Code calculation example:**

```python
def login_code(screen_name, password):
    return 7696 * ord(screen_name[0]) * ord(password[0])
```

For screen name `toctest1` (first char `t` = 116) and password `testpass1`
(first char `t` = 116): `7696 * 116 * 116 = 103,547,776`.

**Example:**

```
toc2_login login.oscar.aol.com 5190 toctest1 0x2408105c23001130 english "TIC:MyClient" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776
```

On success:

```
SIGN_ON:TOC2.0
NICK:toctest1
CONFIG2:<config data>
```

---

## 3. Client → Server Commands (TOC 1)

All client commands are lowercase, space-separated, and sent as FLAP DATA
frames (null-terminated). Arguments containing spaces should be enclosed in
quotes. Screen names must be **normalized** (lowercased, spaces removed).
Message content must be **escaped** (see [Escaping Rules](#8-escaping--encoding-rules)).

### toc_init_done

Tells the server the client is ready to go online. Must be sent within 30
seconds of the signon command, and only after `SIGN_ON` is received.

```
toc_init_done
```

### toc_send_im

Send an instant message to a user. The message may contain basic HTML.

```
toc_send_im <destination_user> <message> [auto]
```

| Parameter        | Description                                             |
|------------------|---------------------------------------------------------|
| destination_user | Normalized screen name of the recipient                 |
| message          | Quoted, escaped message (may contain HTML)              |
| auto             | Optional literal string `auto` to mark as auto-response |

**Examples:**

```
toc_send_im toctest2 "Hello there!"
toc_send_im toctest2 "I am away right now" auto
toc_send_im toctest2 "Check out \$100 deals"
```

### toc_add_buddy

Add one or more buddies to the buddy list. This subscribes to their presence
updates. Does not modify saved config (TOC 1 only — use `toc_set_config` to
persist).

```
toc_add_buddy <buddy1> [<buddy2> ...]
```

**Example:**

```
toc_add_buddy toctest2 joe mike
```

### toc_remove_buddy

Remove one or more buddies from the buddy list. Does not modify saved config.

```
toc_remove_buddy <buddy1> [<buddy2> ...]
```

**Example:**

```
toc_remove_buddy toctest2
```

### toc_set_config

Save the buddy list configuration on the server. The config is a line-oriented
format where the first character is the item type, followed by a space, then
the value. Enclose the entire config in quotes.

```
toc_set_config <config_string>
```

**Config item types:**

| Prefix | Description                                                                             |
|--------|-----------------------------------------------------------------------------------------|
| `g`    | Buddy group name. All buddies until the next `g` or end of config belong to this group. |
| `b`    | Buddy screen name                                                                       |
| `p`    | Permit list entry                                                                       |
| `d`    | Deny list entry                                                                         |
| `m`    | Permit/Deny mode: `1`=Permit All, `2`=Deny All, `3`=Permit Some, `4`=Deny Some          |

**Example:**

```
toc_set_config "m 1
g Buddies
b toctest2
b joe
g Coworkers
b mike
d spammer123
"
```

### toc_get_status

Query the online status of a user. Returns an `UPDATE_BUDDY` message if
online, or an `ERROR` if the user is not available.

```
toc_get_status <screen_name>
```

**Example:**

```
toc_get_status toctest2
```

### toc_set_info

Set the user's profile information (HTML).

```
toc_set_info <info_html>
```

**Example:**

```
toc_set_info "<b>Hello!</b> I love AIM."
```

### toc_get_info

Request a user's profile. The server responds with a `GOTO_URL` containing a
URL to view the profile, or an `ERROR`.

```
toc_get_info <screen_name>
```

**Example:**

```
toc_get_info toctest2
```

### toc_set_away

Set or clear the away message. If a message is provided, the user's
unavailable flag is set. If omitted, the flag is cleared.

```
toc_set_away [<away_message>]
```

**Examples:**

```
toc_set_away "Gone fishing! <b>BRB</b>"
toc_set_away
```

### toc_set_idle

Set the idle time in seconds. If 0, the user is marked as active. The server
auto-increments the idle counter, so only call this once.

```
toc_set_idle <seconds>
```

**Examples:**

```
toc_set_idle 300
toc_set_idle 0
```

### toc_set_caps

Declare the client's capabilities. All supported capabilities must be sent at
once. Capabilities are represented as UUIDs (see
[Capabilities](#9-capabilities-uuids)).

```
toc_set_caps [<uuid1> [<uuid2> ...]]
```

**Example:**

```
toc_set_caps 09461343-4C7F-11D1-8222-444553540000 09461345-4C7F-11D1-8222-444553540000
```

### toc_evil

Warn (evil) another user. You can only warn users who have recently sent you
an IM.

```
toc_evil <screen_name> <norm|anon>
```

| Type   | Effect                                                                  |
|--------|-------------------------------------------------------------------------|
| `norm` | Normal warning (+20% to target's warning level, your identity revealed) |
| `anon` | Anonymous warning (+10%, your identity hidden)                          |

**Example:**

```
toc_evil spammer123 anon
```

### toc_add_permit

Add users to the permit list. If currently in deny mode, switches to permit
mode first. With no arguments and in deny mode, switches to permit-none.

```
toc_add_permit [<user1> [<user2> ...]]
```

**Example:**

```
toc_add_permit toctest2 joe
```

### toc_add_deny

Add users to the deny (block) list. If currently in permit mode, switches to
deny mode first. With no arguments and in permit mode, switches to deny-none.

```
toc_add_deny [<user1> [<user2> ...]]
```

**Example:**

```
toc_add_deny spammer123
```

### toc_chat_join

Join a chat room on the specified exchange. Exchange should be `4` for
standard chat rooms. The server responds with `CHAT_JOIN` on success or
`ERROR` on failure.

```
toc_chat_join <exchange> <chat_room_name>
```

**Example:**

```
toc_chat_join 4 "My Chat Room"
```

### toc_chat_send

Send a message to a chat room. Use the chat room ID received in the
`CHAT_JOIN` response. Since reflection is always on, you will receive your own
message back as a `CHAT_IN`.

```
toc_chat_send <chat_room_id> <message>
```

**Example:**

```
toc_chat_send 0 "Hello everyone!"
```

### toc_chat_whisper

Send a private message within a chat room directed at a specific user.

```
toc_chat_whisper <chat_room_id> <destination_user> <message>
```

**Example:**

```
toc_chat_whisper 0 toctest2 "Can you see this?"
```

### toc_chat_invite

Invite one or more users to a chat room you are currently in.

```
toc_chat_invite <chat_room_id> <invite_message> <buddy1> [<buddy2> ...]
```

**Example:**

```
toc_chat_invite 0 "Come join us!" toctest2 joe
```

### toc_chat_accept

Accept a chat invitation received via `CHAT_INVITE`. The server will respond
with `CHAT_JOIN`.

```
toc_chat_accept <chat_room_id>
```

**Example:**

```
toc_chat_accept 5
```

### toc_chat_leave

Leave a chat room.

```
toc_chat_leave <chat_room_id>
```

**Example:**

```
toc_chat_leave 0
```

### toc_set_dir

Set directory information. Fields are colon-separated within a quoted string.

```
toc_set_dir <info_string>
```

**Fields (colon-separated):** `"first_name":"middle_name":"last_name":"maiden_name":"city":"state":"country":"email":"allow_web_search"`

**Example:**

```
toc_set_dir "John":"":"Doe":"":"New York":"NY":"US":"john@example.com":""
```

### toc_get_dir

Get a user's directory information. Returns a `GOTO_URL` or `ERROR`.

```
toc_get_dir <screen_name>
```

**Example:**

```
toc_get_dir toctest2
```

### toc_dir_search

Search the user directory by field. Returns a `GOTO_URL` or `ERROR`.

```
toc_dir_search <search_fields>
```

**Fields (colon-separated):** `"first_name":"middle_name":"last_name":"maiden_name":"city":"state":"country":"email"`

You can search by keyword by placing it in the 11th position:

```
toc_dir_search "::::::::":"":"search term"
```

**Example:**

```
toc_dir_search "John":"":"Doe":"":"":"":"":""
```

### toc_format_nickname

Reformat the capitalization/spacing of your screen name. Returns
`ADMIN_NICK_STATUS` and `NICK` on success, or `ERROR` on failure.

```
toc_format_nickname <new_format>
```

**Example:**

```
toc_format_nickname "TocTest1"
```

### toc_change_passwd

Change your password. Returns `ADMIN_PASSWD_STATUS` on success or `ERROR` on
failure. Passwords are sent as plaintext (not roasted). Special characters
must be backslash-escaped (see [Escaping Rules](#8-escaping--encoding-rules)).

Note: Because passwords are sent in cleartext (unlike the roasted password at
login), this command is not secure against network eavesdropping.

```
toc_change_passwd <old_password> <new_password>
```

**Examples:**

```
toc_change_passwd oldpass newpass
toc_change_passwd "my old pass" "my new pass"
toc_change_passwd oldpa\$\$ newpa\$\$
```

### toc_rvous_accept

Accept a rendezvous proposal (e.g. file transfer) from another user.

```
toc_rvous_accept <screen_name> <cookie> <service_uuid>
```

| Parameter    | Description                                            |
|--------------|--------------------------------------------------------|
| screen_name  | The user who sent the proposal                         |
| cookie       | Base64-encoded cookie from the `RVOUS_PROPOSE` message |
| service_uuid | UUID of the service being accepted                     |

**Example:**

```
toc_rvous_accept toctest2 fUdgNuQ6AAA= 09461343-4C7F-11D1-8222-444553540000
```

### toc_rvous_cancel

Cancel/decline a rendezvous proposal from another user.

```
toc_rvous_cancel <screen_name> <cookie> <service_uuid>
```

**Example:**

```
toc_rvous_cancel toctest2 fUdgNuQ6AAA= 09461343-4C7F-11D1-8222-444553540000
```

---

## 4. Client → Server Commands (TOC 2)

TOC 2 commands use the `toc2_` prefix and operate on the server-side buddy
list (feedbag) directly. Changes are automatically saved.

### toc2_send_im

Same syntax as `toc_send_im`.

```
toc2_send_im <destination_user> <message> [auto]
```

**Example:**

```
toc2_send_im toctest2 "Hey there!"
```

### toc2_send_im_enc

Send an encoded instant message. Supports encoding and language parameters.

```
toc2_send_im_enc <destination_user> "F" <encoding> <language> <message> [auto]
```

| Parameter        | Description                             |
|------------------|-----------------------------------------|
| destination_user | Normalized screen name                  |
| "F"              | Unknown flag, always `F`                |
| encoding         | Character encoding (e.g. `A` for ASCII) |
| language         | Language code (e.g. `en`)               |
| message          | Quoted, escaped message                 |
| auto             | Optional `auto` for auto-response       |

**Example:**

```
toc2_send_im_enc toctest2 "F" A en "Hello from TOC2!"
```

### toc2_set_pdmode

Set the permit/deny privacy mode.

```
toc2_set_pdmode <mode>
```

| Mode | Description            |
|------|------------------------|
| 1    | Allow all (default)    |
| 2    | Block all              |
| 3    | Allow permit list only |
| 4    | Block deny list only   |
| 5    | Allow buddy list only  |

**Example:**

```
toc2_set_pdmode 1
```

### toc2_new_group

Create a new buddy list group.

```
toc2_new_group <group_name>
```

**Example:**

```
toc2_new_group "Work Friends"
```

### toc2_del_group

Delete a buddy list group and all buddies within it.

```
toc2_del_group <group_name>
```

**Example:**

```
toc2_del_group "Work Friends"
```

### toc2_new_buddies

Add buddies to the server-side buddy list using a config-format string. If the
specified group does not exist, it will be created.

```
toc2_new_buddies <config_format>
```

**Config format:** `{g:<group>\nb:<buddy>[:<alias>]\nb:<buddy2>\n}`

Where `\n` is a literal linefeed character (ASCII 10, `0x0A`).

Extended buddy format with alias and note:
`b:<buddy>:<alias>:::::note`

**Examples:**

Add two buddies to the "Friends" group:

```
toc2_new_buddies "{g:Friends\nb:toctest2\nb:joe\n}"
```

Add a buddy with an alias:

```
toc2_new_buddies "{g:Friends\nb:toctest2:Test User 2\n}"
```

### toc2_remove_buddy

Remove one or more buddies from a group. The last argument is always the group
name.

```
toc2_remove_buddy <screen_name> [<screen_name> ...] <group>
```

**Examples:**

```
toc2_remove_buddy toctest2 "Friends"
toc2_remove_buddy toctest2 joe "Friends"
```

### toc2_add_permit

Add users to the permit list (feedbag-based).

```
toc2_add_permit <screen_name> [<screen_name> ...]
```

**Example:**

```
toc2_add_permit toctest2 joe
```

### toc2_remove_permit

Remove users from the permit list.

```
toc2_remove_permit <screen_name> [<screen_name> ...]
```

**Example:**

```
toc2_remove_permit toctest2
```

### toc2_add_deny

Add users to the deny (block) list (feedbag-based).

```
toc2_add_deny <screen_name> [<screen_name> ...]
```

**Example:**

```
toc2_add_deny spammer
```

### toc2_remove_deny

Remove users from the deny (block) list.

```
toc2_remove_deny <screen_name> [<screen_name> ...]
```

**Example:**

```
toc2_remove_deny spammer
```

### toc2_client_event

Send a typing notification to another user.

```
toc2_client_event <screen_name> <typing_status>
```

| Status | Description                  |
|--------|------------------------------|
| 0      | Idle (no activity)           |
| 1      | Text entered (paused typing) |
| 2      | Currently typing             |

**Example:**

```
toc2_client_event toctest2 2
```

---

## 5. Server → Client Messages (TOC 1)

Server messages use colons as separators. Messages are NOT null-terminated.
When parsing, be aware that message content (IMs, chat messages) may contain
colons — split with a maximum field count appropriate to each command.

### SIGN_ON

Sent after a successful login.

```
SIGN_ON:<protocol_version>
```

**Example:**

```
SIGN_ON:TOC1.0
```

### CONFIG

The user's saved configuration (buddy list, permit/deny). Only sent for TOC 1
logins. Config may be empty if none was previously saved.

```
CONFIG:<config_data>
```

Config format uses space-separated item types (same format as `toc_set_config`):

```
CONFIG:m 1
g Buddies
b toctest2
b joe
d spammer123
```

Config may be empty (`CONFIG:`) if no configuration has been saved.

### NICK

The user's properly formatted screen name.

```
NICK:<formatted_screen_name>
```

**Example:**

```
NICK:TocTest1
```

### IM_IN

An incoming instant message.

```
IM_IN:<source_user>:<auto_response T/F>:<message>
```

Everything after the third colon is the message (may contain additional
colons).

**Examples:**

```
IM_IN:TocTest2:F:Hello there!
IM_IN:TocTest2:T:I am away from my computer right now.
IM_IN:TocTest2:F:<b>Bold</b> and <i>italic</i>
```

### UPDATE_BUDDY

Buddy presence update. Handles arrivals, departures, and status changes.

```
UPDATE_BUDDY:<screen_name>:<online T/F>:<warning_level>:<signon_time>:<idle_minutes>:<user_class>
```

| Field         | Description                            |
|---------------|----------------------------------------|
| screen_name   | Formatted screen name                  |
| online        | `T` if online, `F` if offline          |
| warning_level | Warning percentage (0-100)             |
| signon_time   | Unix epoch timestamp of signon         |
| idle_minutes  | Minutes idle (0 = active)              |
| user_class    | 2-3 character class string (see below) |

**User class characters:**

| Position | Char  | Meaning                      |
|----------|-------|------------------------------|
| uc[0]    | `' '` | Normal                       |
| uc[0]    | `'A'` | On AOL                       |
| uc[1]    | `' '` | Normal                       |
| uc[1]    | `'A'` | Admin                        |
| uc[1]    | `'U'` | Unconfirmed                  |
| uc[1]    | `'O'` | OSCAR Free (normal AIM user) |
| uc[1]    | `'C'` | Mobile/wireless              |
| uc[2]    | `' '` | Available                    |
| uc[2]    | `'U'` | Unavailable (away)           |

**Examples:**

```
UPDATE_BUDDY:TocTest2:T:0:1711036800:0: O
UPDATE_BUDDY:TocTest2:T:0:1711036800:0: U
UPDATE_BUDDY:TocTest2:F:0:0:0:
UPDATE_BUDDY:TocTest2:T:20:1711036800:5: OU
```

### ERROR

An error response. May include a screen name or sub-error code as a variable
argument.

```
ERROR:<error_code>[:<variable>]
```

**Example:**

```
ERROR:901:toctest2
ERROR:980
```

See [Error Codes](#7-error-codes) for the full list.

### EVILED

The user has been warned.

```
EVILED:<new_warning_level>:<eviler_screen_name>
```

If the warning was anonymous, the eviler field is empty.

**Examples:**

```
EVILED:20:TocTest2
EVILED:10:
```

### CHAT_JOIN

Successfully joined a chat room. The chat room ID is an integer assigned by
the server — store it for subsequent chat commands.

```
CHAT_JOIN:<chat_room_id>:<chat_room_name>
```

**Example:**

```
CHAT_JOIN:0:My Chat Room
```

### CHAT_IN

A message received in a chat room.

```
CHAT_IN:<chat_room_id>:<source_user>:<whisper T/F>:<message>
```

**Example:**

```
CHAT_IN:0:TocTest2:F:Hello everyone!
```

### CHAT_UPDATE_BUDDY

Users have joined or left a chat room. The first message of this type for a
room contains the initial user list.

```
CHAT_UPDATE_BUDDY:<chat_room_id>:<inside T/F>:<user1>[:<user2>...]
```

| Field  | Description                               |
|--------|-------------------------------------------|
| inside | `T` = users arrived, `F` = users departed |

**Examples:**

```
CHAT_UPDATE_BUDDY:0:T:TocTest1:TocTest2
CHAT_UPDATE_BUDDY:0:F:TocTest2
```

### CHAT_INVITE

An invitation to join a chat room.

```
CHAT_INVITE:<chat_room_name>:<chat_room_id>:<sender>:<message>
```

**Example:**

```
CHAT_INVITE:My Chat Room:5:TocTest2:Come join us!
```

### CHAT_LEFT

Confirmation that you have left a chat room.

```
CHAT_LEFT:<chat_room_id>
```

**Example:**

```
CHAT_LEFT:0
```

### GOTO_URL

Directs the client to open a URL (for profiles, directory info, search
results).

```
GOTO_URL:<window_name>:<url>
```

**Example:**

```
GOTO_URL:profile:info?cookie=abc123&user=toctest2&from=toctest1
```

### DIR_STATUS

Result of a `toc_set_dir` command.

```
DIR_STATUS:<return_code>
```

Return code 0 indicates success.

### ADMIN_NICK_STATUS

Result of a `toc_format_nickname` command.

```
ADMIN_NICK_STATUS:<return_code>
```

Return code 0 indicates success.

**Example:**

```
ADMIN_NICK_STATUS:0
```

### ADMIN_PASSWD_STATUS

Result of a `toc_change_passwd` command.

```
ADMIN_PASSWD_STATUS:<return_code>
```

Return code 0 indicates success.

### RVOUS_PROPOSE

Another user proposes a rendezvous (file transfer, etc.).

```
RVOUS_PROPOSE:<user>:<uuid>:<cookie>:<seq>:<rvous_ip>:<proposer_ip>:<verified_ip>:<port>[:<tlv_tag>:<tlv_value>...]
```

| Field       | Description                        |
|-------------|------------------------------------|
| user        | Screen name of the proposer        |
| uuid        | Service UUID (e.g. file transfer)  |
| cookie      | Base64-encoded session cookie      |
| seq         | Sequence number                    |
| rvous_ip    | Rendezvous IP address              |
| proposer_ip | Proposer's IP address              |
| verified_ip | Server-verified IP address         |
| port        | Port number for direct connection  |
| tlv pairs   | Additional base64-encoded TLV data |

**Example:**

```
RVOUS_PROPOSE:TocTest2:09461343-4C7F-11D1-8222-444553540000:fUdgNuQ6AAA=:1:192.168.1.5:192.168.1.5:203.0.113.1:5190:10001:ABIAAgAAAAEA
```

### PAUSE

Server requests the client to pause. A new `SIGN_ON` will follow when the
server is ready. The buddy list and permit/deny items must be resent,
followed by `toc_init_done`.

```
PAUSE
```

---

## 6. Server → Client Messages (TOC 2)

TOC 2 extends the server messages with richer variants. When logged in via
`toc2_signon` or `toc2_login`, these messages are sent instead of (or in
addition to) their TOC 1 equivalents.

### SIGN_ON (TOC 2)

```
SIGN_ON:TOC2.0
```

### CONFIG2

Server-side buddy list configuration, sent at login. Fields are separated by
linefeeds (`\n`, ASCII 10). Colons separate sub-fields within each line.

```
CONFIG2:<config_lines>
```

**Config line types:**

| Prefix  | Format                                 | Description                                   |
|---------|----------------------------------------|-----------------------------------------------|
| `g:`    | `g:<group_name>`                       | Buddy group                                   |
| `b:`    | `b:<screen_name>[:<alias>][:::::note]` | Buddy entry (with optional alias and note)    |
| `d:`    | `d:<screen_name>`                      | Deny list entry                               |
| `p:`    | `p:<screen_name>`                      | Permit list entry                             |
| `m:`    | `m:<mode>`                             | Privacy mode (1-5, same as `toc2_set_pdmode`) |
| `done:` | `done:`                                | End of config                                 |

**Example:**

```
CONFIG2:g:Buddies
b:toctest2:Test User
b:joe
d:spammer
m:1
done:
```

### NICK (TOC 2)

Same as TOC 1:

```
NICK:<formatted_screen_name>
```

### IM_IN2

Incoming instant message (TOC 2 variant). Adds a whisper field.

```
IM_IN2:<source_user>:<auto_response T/F>:<whisper T/F>:<message>
```

**Example:**

```
IM_IN2:TocTest2:F:F:Hello from TOC2!
```

### IM_IN_ENC2

Incoming encoded instant message (TOC 2 with `toc2_login`). Includes user
class and language information.

```
IM_IN_ENC2:<user>:<auto T/F>:<unknown1>:<unknown2>:<user_class>:<unknown3>:<unknown4>:<language>:<message>
```

| Field      | Description                                         |
|------------|-----------------------------------------------------|
| user       | Sender's screen name                                |
| auto       | `T` if auto-response, `F` otherwise                 |
| unknown1   | Typically `F`                                       |
| unknown2   | Typically `T`                                       |
| user_class | Same as UPDATE_BUDDY user class (e.g. ` O `, ` OU`) |
| unknown3   | Typically `F`                                       |
| unknown4   | Typically `L`                                       |
| language   | Language code (e.g. `en`)                           |
| message    | The message content (may contain colons)            |

**Example:**

```
IM_IN_ENC2:TocTest2:F:F:T: O :F:L:en:Hello from TOC2!
IM_IN_ENC2:TocTest2:T:F:T: OU:F:L:en:I am away right now.
```

### UPDATE_BUDDY2

Buddy presence update (TOC 2). Same as `UPDATE_BUDDY` with a trailing field.

```
UPDATE_BUDDY2:<screen_name>:<online T/F>:<warning_level>:<signon_time>:<idle_minutes>:<user_class>:<unknown>
```

The trailing unknown field is typically empty.

**Examples:**

```
UPDATE_BUDDY2:TocTest2:T:0:1711036800:0: O :
UPDATE_BUDDY2:TocTest2:F:0:0:0:   :
```

### BUDDY_CAPS2

Sent alongside `UPDATE_BUDDY2` to describe a buddy's capabilities.

```
BUDDY_CAPS2:<screen_name>:<cap1>,<cap2>,...
```

Capabilities are UUIDs (see [Capabilities](#9-capabilities-uuids)).

**Example:**

```
BUDDY_CAPS2:TocTest2:748f2420-6287-11d1-8222-444553540000,09461343-4c7f-11d1-8222-444553540000
```

### CHAT_IN_ENC

Encoded chat message (TOC 2 with `toc2_login`).

```
CHAT_IN_ENC:<chat_room_id>:<source_user>:<whisper T/F>:<unknown>:<language>:<message>
```

The unknown field is typically `A`.

**Example:**

```
CHAT_IN_ENC:0:TocTest2:F:A:en:Hello everyone!
```

### NEW_BUDDY_REPLY2

Confirmation after adding a buddy via `toc2_new_buddies`.

```
NEW_BUDDY_REPLY2:<screen_name>:<action>
```

| Action  | Description                    |
|---------|--------------------------------|
| `added` | Buddy was added successfully   |
| `auth`  | ICQ authorization request sent |

**Example:**

```
NEW_BUDDY_REPLY2:toctest2:added
```

### CLIENT_EVENT2

Typing notification from another user.

```
CLIENT_EVENT2:<screen_name>:<typing_status>
```

| Status | Description                  |
|--------|------------------------------|
| 0      | No activity (stopped typing) |
| 1      | Text entered (paused)        |
| 2      | Currently typing             |

**Example:**

```
CLIENT_EVENT2:TocTest2:2
```

### INSERTED2

Dynamic buddy list update — items added from another session.

**Group added:**

```
INSERTED2:g:<group_name>
```

**Buddy added:**

```
INSERTED2:b:<alias>:<screen_name>:<group>
```

**Deny list entry added:**

```
INSERTED2:d:<screen_name>
```

**Permit list entry added:**

```
INSERTED2:p:<screen_name>
```

**Examples:**

```
INSERTED2:g:New Group
INSERTED2:b:My Friend:toctest2:Buddies
INSERTED2:b::joe:Buddies
INSERTED2:d:spammer
INSERTED2:p:trusteduser
```

### DELETED2

Dynamic buddy list update — items removed from another session.

**Group deleted:**

```
DELETED2:g:<group_name>
```

**Buddy deleted:**

```
DELETED2:b:<screen_name>:<group>
```

**Deny list entry removed:**

```
DELETED2:d:<screen_name>
```

**Permit list entry removed:**

```
DELETED2:p:<screen_name>
```

**Examples:**

```
DELETED2:g:Old Group
DELETED2:b:toctest2:Buddies
DELETED2:d:spammer
```

### BART2

Buddy icon (Buddy Art) information. Structure is not fully understood.

```
BART2:<screen_name>:<data>
```

---

## 7. Error Codes

Errors are sent as `ERROR:<code>[:<variable>]`. The variable argument (if
present) is typically a screen name or sub-error code.

### General Errors

| Code | Description                                  |
|------|----------------------------------------------|
| 901  | `$1` not currently available                 |
| 902  | Warning of `$1` not currently available      |
| 903  | Message dropped, server speed limit exceeded |

### Admin Errors

| Code | Description                                |
|------|--------------------------------------------|
| 911  | Error validating input                     |
| 912  | Invalid account                            |
| 913  | Error encountered while processing request |
| 914  | Service unavailable                        |

### Chat Errors

| Code | Description                 |
|------|-----------------------------|
| 950  | Chat in `$1` is unavailable |

### IM & Info Errors

| Code | Description                                         |
|------|-----------------------------------------------------|
| 960  | Sending messages too fast to `$1`                   |
| 961  | Missed an IM from `$1` because it was too big       |
| 962  | Missed an IM from `$1` because it was sent too fast |

### Directory Errors

| Code | Description                         |
|------|-------------------------------------|
| 970  | Failure                             |
| 971  | Too many matches                    |
| 972  | Need more qualifiers                |
| 973  | Dir service temporarily unavailable |
| 974  | Email lookup restricted             |
| 975  | Keyword ignored                     |
| 976  | No keywords                         |
| 977  | Language not supported              |
| 978  | Country not supported               |
| 979  | Failure unknown `$1`                |

### Auth Errors

| Code | Description                                               |
|------|-----------------------------------------------------------|
| 980  | Incorrect nickname or password                            |
| 981  | Service temporarily unavailable                           |
| 982  | Warning level too high to sign on                         |
| 983  | Connecting/disconnecting too frequently (wait 10 minutes) |
| 989  | Unknown signon error `$1`                                 |

**Sub-error codes for 989:**

| Sub-code | Description                     |
|----------|---------------------------------|
| 0        | Signed on too soon              |
| 7        | Invalid screen name or password |
| 17       | Suspended account               |

---

## 8. Escaping & Encoding Rules

### 8.1 Client → Server (Encoding)

When sending commands to the server, certain characters must be
**backslash-escaped** whether inside quotes or not:

| Character | Escaped |
|-----------|---------|
| `\`       | `\\`    |
| `$`       | `\$`    |
| `"`       | `\"`    |
| `(`       | `\(`    |
| `)`       | `\)`    |
| `{`       | `\{`    |
| `}`       | `\}`    |
| `[`       | `\[`    |
| `]`       | `\]`    |

**Example:** To send the message `He said "hello" (wow) for $5`:

```
toc_send_im toctest2 "He said \"hello\" \(wow\) for \$5"
```

### 8.2 Screen Name Normalization

When sending screen names to the server, **normalize** them:

1. Convert to lowercase.
2. Remove all spaces.

Example: `Toc Test 1` → `toctest1`

### 8.3 Server → Client (No Encoding)

Server messages are NOT encoded. They use colons as delimiters. When parsing,
limit the number of splits to avoid breaking messages that contain colons.

### 8.4 Null Termination

- **Client → Server:** All FLAP DATA payloads MUST end with a null byte
  (`0x00`). Include it in the FLAP data length.
- **Server → Client:** FLAP DATA payloads are NOT null-terminated.

---

## 9. Capabilities (UUIDs)

Capabilities indicate which features a client supports. They are set via
`toc_set_caps` and reported via `BUDDY_CAPS2`.

### Standard Capabilities

| Name            | UUID                                   |
|-----------------|----------------------------------------|
| Voice Chat      | `09461341-4C7F-11D1-8222-444553540000` |
| File Send       | `09461343-4C7F-11D1-8222-444553540000` |
| Image           | `09461345-4C7F-11D1-8222-444553540000` |
| Buddy Icon      | `09461346-4C7F-11D1-8222-444553540000` |
| Stocks          | `09461347-4C7F-11D1-8222-444553540000` |
| File Get        | `09461348-4C7F-11D1-8222-444553540000` |
| Games           | `0946134A-4C7F-11D1-8222-444553540000` |
| Send Buddy List | `0946134B-4C7F-11D1-8222-444553540000` |
| AIM/ICQ Interop | `0946134D-4C7F-11D1-8222-444553540000` |
| Chat            | `748F2420-6287-11D1-8222-444553540000` |

### Short Capability Format

Some clients send capabilities as short hex codes (1-4 hex digits). These
expand to the full OSCAR capability UUID format:
`0946XXYY-4C7F-11D1-8222-444553540000` where `XXYY` is the short code
zero-padded to 4 hex digits.

**Example:** Short cap `1343` → `09461343-4C7F-11D1-8222-444553540000` (File Send)

---

## 10. Complete Session Examples

### 10.1 TOC 1 Session (Minimal)

This example shows a complete TOC 1 session: login, add a buddy, send a
message, and disconnect.

**Wire-level (showing FLAP framing conceptually):**

```
→ TCP connect to server:9898
→ "FLAPON\r\n\r\n"
← [FLAP SIGNON] version=1
→ [FLAP SIGNON] version=1, TLV(1)="toctest1"
→ [FLAP DATA]   toc_signon login.oscar.aol.com 5190 toctest1 0x2408105c23001130 english "TIC:Example"
← [FLAP DATA]   SIGN_ON:TOC1.0
← [FLAP DATA]   CONFIG:m 1\ng Buddies\nb toctest2\n
← [FLAP DATA]   NICK:toctest1
→ [FLAP DATA]   toc_add_buddy toctest2
→ [FLAP DATA]   toc_init_done
← [FLAP DATA]   UPDATE_BUDDY:toctest2:T:0:1711036800:0: O
→ [FLAP DATA]   toc_send_im toctest2 "Hello!"
→ [FLAP DATA]   toc_set_away "Gone fishing"
→ [FLAP SIGNOFF]
```

### 10.2 TOC 2 Session (toc2_login)

```
→ TCP connect to server:9898
→ "FLAPON\r\n\r\n"
← [FLAP SIGNON] version=1
→ [FLAP SIGNON] version=1, TLV(1)="toctest1"
→ [FLAP DATA]   toc2_login login.oscar.aol.com 5190 toctest1 0x2408105c23001130 english "TIC:Example" 160 US "" "" 3 0 30303 -kentucky -utf8 103547776
← [FLAP DATA]   SIGN_ON:TOC2.0
← [FLAP DATA]   NICK:toctest1
← [FLAP DATA]   CONFIG2:g:Buddies\nb:toctest2:Test User\nm:1\ndone:\n
→ [FLAP DATA]   toc_init_done
← [FLAP DATA]   UPDATE_BUDDY2:toctest2:T:0:1711036800:0: O :
← [FLAP DATA]   BUDDY_CAPS2:toctest2:748f2420-6287-11d1-8222-444553540000
→ [FLAP DATA]   toc2_new_buddies "{g:Friends\nb:joe\n}"
← [FLAP DATA]   NEW_BUDDY_REPLY2:joe:added
→ [FLAP DATA]   toc2_send_im_enc toctest2 "F" A en "Hello from TOC2!"
→ [FLAP DATA]   toc2_client_event toctest2 2
→ [FLAP DATA]   toc2_set_pdmode 1
→ [FLAP SIGNOFF]
```

### 10.3 Chat Session

```
→ toc_chat_join 4 "Retro Chat"
← CHAT_JOIN:0:Retro Chat
← CHAT_UPDATE_BUDDY:0:T:toctest1
→ toc_chat_send 0 "Hello room!"
← CHAT_IN:0:toctest1:F:Hello room!
← CHAT_UPDATE_BUDDY:0:T:toctest2
→ toc_chat_invite 0 "Come chat!" joe
→ toc_chat_send 0 "Welcome toctest2!"
← CHAT_IN:0:toctest1:F:Welcome toctest2!
→ toc_chat_leave 0
← CHAT_LEFT:0
```

### 10.4 Python Client Example

A minimal Python client that connects, logs in, sends a message, and reads
responses:

```python
import socket
import struct


ROAST = "Tic/Toc"


def roast_password(password):
    result = []
    for i, ch in enumerate(password):
        xored = ord(ch) ^ ord(ROAST[i % len(ROAST)])
        result.append(f"{xored:02x}")
    return "0x" + "".join(result)


def send_flap(sock, frame_type, seq, payload):
    data = payload.encode("ascii") if isinstance(payload, str) else payload
    if frame_type == 2:
        data += b"\x00"  # null-terminate DATA frames
    header = struct.pack("!BBHH", 0x2A, frame_type, seq, len(data))
    sock.sendall(header + data)
    return seq + 1


def recv_flap(sock):
    header = b""
    while len(header) < 6:
        chunk = sock.recv(6 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed")
        header += chunk
    marker, frame_type, seq, length = struct.unpack("!BBHH", header)
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise ConnectionError("Connection closed")
        payload += chunk
    return frame_type, seq, payload


def normalize(screen_name):
    return screen_name.lower().replace(" ", "")


def escape(text):
    for ch in r'\$"(){}[]':
        text = text.replace(ch, "\\" + ch)
    return text


def main():
    HOST = "127.0.0.1"
    PORT = 9898
    USERNAME = "toctest1"
    PASSWORD = "testpass1"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.settimeout(5)

    # Step 1: Send FLAPON
    sock.sendall(b"FLAPON\r\n\r\n")

    # Step 2: Receive server SIGNON frame
    frame_type, seq, payload = recv_flap(sock)
    assert frame_type == 1, f"Expected SIGNON frame, got {frame_type}"

    # Step 3: Send client SIGNON frame
    sn = normalize(USERNAME).encode("ascii")
    signon_payload = struct.pack("!IHH", 1, 1, len(sn)) + sn
    seq_out = send_flap(sock, 1, 0, signon_payload)

    # Step 4: Send toc_signon
    roasted = roast_password(PASSWORD)
    cmd = f'toc_signon login.oscar.aol.com 5190 {normalize(USERNAME)} {roasted} english "TIC:PythonTOC"'
    seq_out = send_flap(sock, 2, seq_out, cmd)

    # Step 5: Read responses
    for _ in range(10):
        try:
            frame_type, seq, payload = recv_flap(sock)
            if frame_type == 2:
                print(f"← {payload.decode('ascii', errors='replace')}")
        except socket.timeout:
            break

    # Step 6: Send init_done
    seq_out = send_flap(sock, 2, seq_out, "toc_init_done")

    # Step 7: Send a message
    msg = escape("Hello from Python!")
    seq_out = send_flap(sock, 2, seq_out, f'toc_send_im toctest2 "{msg}"')

    # Read any remaining responses
    for _ in range(10):
        try:
            frame_type, seq, payload = recv_flap(sock)
            if frame_type == 2:
                print(f"← {payload.decode('ascii', errors='replace')}")
        except socket.timeout:
            break

    # Disconnect
    send_flap(sock, 4, seq_out, b"")
    sock.close()


if __name__ == "__main__":
    main()
```
