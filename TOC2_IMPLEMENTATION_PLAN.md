# TOC 2 Buddy List Commands Implementation Plan

## Overview
Implement TOC 2 commands for buddy list management using FeedbagService. These commands should integrate with existing TOC 1 handlers where possible, or create new handlers if no existing functionality exists.

## Commands to Implement

1. `toc2_new_buddies` - Add buddies in config format
2. `toc2_remove_buddy` - Remove buddy(ies) from a group
3. `toc2_new_group` - Create a new buddy group
4. `toc2_del_group` - Delete a buddy group
5. `toc2_add_deny` - Add user(s) to deny list
6. `toc2_remove_deny` - Remove user(s) from deny list
7. `toc2_add_permit` - Add user(s) to permit list
8. `toc2_remove_permit` - Remove user(s) from permit list

## Implementation Checklist

### Phase 1: Setup and Infrastructure

- [ ] **1.1** Review TOC2 specification from the provided URL
  - Understand config format syntax: `{g:group<lf>b:buddy1<lf>b:buddy2<lf>}`
  - Understand command syntax and parameters
  - Note that screennames should be normalized

- [ ] **1.2** Review existing TOC 1 implementations
  - `AddBuddy` (toc_add_buddy) - uses BuddyService
  - `RemoveBuddy` (toc_remove_buddy) - uses BuddyService
  - `AddPermit` (toc_add_permit) - uses PermitDenyService
  - `AddDeny` (toc_add_deny) - uses PermitDenyService
  - Note: TOC 1 doesn't have group management or remove permit/deny

- [ ] **1.3** Review FeedbagService interface and usage
  - `UpsertItem` - for adding/updating feedbag items
  - `DeleteItem` - for removing feedbag items
  - FeedbagManager.Feedbag() - for retrieving current feedbag state
  - Understand FeedbagItem structure (ClassID, ItemID, GroupID, Name, TLVLBlock)

- [ ] **1.4** Review helper functions needed
  - `parseArgs` - already exists for parsing command arguments
  - Screen name normalization - check if needed
  - Item ID generation - need to find next available ID (see mgmt_api.go:randItemID)

### Phase 2: Helper Functions

- [ ] **2.1** Create helper function to parse TOC2 config format
  - Function: `parseTOC2Config(config string) (groups map[string][]string, err error)`
  - Parse format: `{g:group<lf>b:buddy1<lf>b:buddy2<lf>}`
  - Handle linefeed characters (ASCII 10)
  - Return map of group names to buddy lists
  - Handle alias and note fields if present (format: `b:buddy:alias:::::note`)
  - This is the only helper function needed (for config parsing)

Note: All feedbag scanning logic (finding groups, finding next ItemID/GroupID, etc.) should be done inline within each handler function, not in separate helper functions.

### Phase 3: Group Management Commands

- [ ] **3.1** Implement `toc2_new_group`
  - Command syntax: `toc2_new_group <group>` (group should be quoted)
  - Add case to RecvClientCmd switch statement
  - Handler function: `NewGroup(ctx, me, args)`
  - Steps:
    1. Parse group name from args (handle quotes, unescape)
    2. Retrieve current feedbag via FeedbagManager.Feedbag()
    3. Scan feedbag items inline:
       - Check if group already exists (ClassID == FeedbagClassIdGroup, Name == groupName)
       - If exists, return error or success (depending on desired behavior)
       - Find max GroupID by scanning all groups (ClassID == FeedbagClassIdGroup)
       - Calculate next GroupID = maxGroupID + 1 (start from 1, not 0)
    4. Create FeedbagItem with ClassID=FeedbagClassIdGroup, ItemID=nextGroupID, GroupID=0, Name=groupName
    5. Call FeedbagService.UpsertItem() with single item
    6. Return empty response (success) or error

- [ ] **3.2** Implement `toc2_del_group`
  - Command syntax: `toc2_del_group <group>`
  - Add case to RecvClientCmd switch statement
  - Handler function: `DelGroup(ctx, me, args)`
  - Steps:
    1. Parse group name from args
    2. Retrieve current feedbag via FeedbagManager.Feedbag()
    3. Scan feedbag items inline:
       - Find group by name (ClassID == FeedbagClassIdGroup, Name == groupName)
       - If not found, return error
       - Optionally check if group has buddies (ClassID == FeedbagClassIdBuddy, GroupID == groupID)
       - If has buddies, decide whether to prevent deletion or allow it
    4. Create FeedbagItem with ItemID=groupID, GroupID=0 for deletion (need both for DeleteItem)
    5. Call FeedbagService.DeleteItem() with single item
    6. Return empty response or error

### Phase 4: Buddy Management Commands

- [ ] **4.1** Implement `toc2_new_buddies`
  - Command syntax: `toc2_new_buddies <config format>`
  - Add case to RecvClientCmd switch statement
  - Handler function: `NewBuddies(ctx, me, args)`
  - Steps:
    1. Parse config format string (handle quotes, unescape)
    2. Parse config using helper function parseTOC2Config (2.1)
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline to build lookup maps:
       - Map of group names to group ItemIDs
       - Map of existing ItemIDs (to find next available)
       - Map of existing buddies by group (to check duplicates)
    5. For each group in config:
       a. If group doesn't exist in map:
          - Find max GroupID by scanning feedbag
          - Create new group FeedbagItem, add to updates list
          - Add to group name map
       b. For each buddy in group:
          - Normalize buddy screen name using `state.NewIdentScreenName(buddy).String()`
          - Check if buddy already exists in this group (skip if duplicate)
          - Find next available ItemID by scanning existing items
          - Create FeedbagItem with ClassID=FeedbagClassIdBuddy, ItemID=nextItemID, GroupID=groupItemID, Name=normalizedScreenName
          - Handle alias/note if present in config (add to TLVLBlock)
          - Add to updates list
    6. Batch all items and call FeedbagService.UpsertItem() once
    7. Return NEW_BUDDY_REPLY2 responses for each buddy added
    8. Format: `NEW_BUDDY_REPLY2:<buddy>:added` (one per successfully added buddy)

- [ ] **4.2** Complete implementation of `toc2_remove_buddy`
  - Command syntax: `toc2_remove_buddy <screenname> [screenname] ... [screenname] <group>`
  - Already has stub in cmd_client.go (line 1398)
  - Handler function: `RemoveBuddy2(ctx, me, args)` (already exists)
  - Steps:
    1. Parse all arguments (multiple screennames + group name at end)
    2. Normalize all screennames using `state.NewIdentScreenName(sn).String()`
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline:
       - Find group by name (ClassID == FeedbagClassIdGroup, Name == groupName)
       - If group not found, return error
       - For each normalized screenname:
         - Find buddy item (ClassID == FeedbagClassIdBuddy, GroupID == groupID, Name == normalizedScreenName)
         - If found, add to deletion list
    5. If deletion list is empty, return error (no buddies found to delete)
    6. Call FeedbagService.DeleteItem() with all items in deletion list
    7. Return empty response (success) or error

### Phase 5: Permit/Deny Commands

- [ ] **5.1** Implement `toc2_add_permit`
  - Command syntax: `toc2_add_permit <screenname> [screenname] ...`
  - Add case to RecvClientCmd switch statement
  - Handler function: `AddPermit2(ctx, me, args)`
  - Steps:
    1. Parse all screennames from args
    2. Normalize screen names using `state.NewIdentScreenName(sn).String()`
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline:
       - Build set of existing permit screennames (ClassID == FeedbagClassIDPermit)
       - Find max ItemID across all items to determine next available
    5. For each normalized screenname:
       a. Skip if already in permit list (already exists)
       b. Create FeedbagItem with ClassID=FeedbagClassIDPermit, ItemID=nextItemID, GroupID=0, Name=normalizedScreenName
       c. Increment nextItemID for next iteration
       d. Add to updates list
    6. Call FeedbagService.UpsertItem() with all items
    7. Return empty response (success) or error

- [ ] **5.2** Implement `toc2_remove_permit`
  - Command syntax: `toc2_remove_permit <screenname> [screenname] ...`
  - Add case to RecvClientCmd switch statement
  - Handler function: `RemovePermit2(ctx, me, args)`
  - Steps:
    1. Parse all screennames from args
    2. Normalize screen names using `state.NewIdentScreenName(sn).String()`
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline:
       - For each normalized screenname:
         - Find permit item (ClassID == FeedbagClassIDPermit, Name == normalizedScreenName)
         - If found, add to deletion list
    5. If deletion list is empty, return error (no permit entries found)
    6. Call FeedbagService.DeleteItem() with all items in deletion list
    7. Return empty response (success) or error

- [ ] **5.3** Implement `toc2_add_deny`
  - Command syntax: `toc2_add_deny <screenname> [screenname] ...`
  - Add case to RecvClientCmd switch statement
  - Handler function: `AddDeny2(ctx, me, args)`
  - Steps:
    1. Parse all screennames from args
    2. Normalize screen names using `state.NewIdentScreenName(sn).String()`
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline:
       - Build set of existing deny screennames (ClassID == FeedbagClassIDDeny)
       - Find max ItemID across all items to determine next available
       - Check if any normalized screenname matches current user (prevent self-block)
    5. For each normalized screenname:
       a. If matches current user (me.IdentScreenName()), skip (prevent self-block)
       b. Skip if already in deny list (already exists)
       c. Create FeedbagItem with ClassID=FeedbagClassIDDeny, ItemID=nextItemID, GroupID=0, Name=normalizedScreenName
       d. Increment nextItemID for next iteration
       e. Add to updates list
    6. Call FeedbagService.UpsertItem() with all items
    7. Return empty response (success) or error
  - Note: Check existing AddDeny (line 327) for self-block prevention logic reference

- [ ] **5.4** Implement `toc2_remove_deny`
  - Command syntax: `toc2_remove_deny <screenname> [screenname] ...`
  - Add case to RecvClientCmd switch statement
  - Handler function: `RemoveDeny2(ctx, me, args)`
  - Steps:
    1. Parse all screennames from args
    2. Normalize screen names using `state.NewIdentScreenName(sn).String()`
    3. Retrieve current feedbag via FeedbagManager.Feedbag()
    4. Scan feedbag items inline:
       - For each normalized screenname:
         - Find deny item (ClassID == FeedbagClassIDDeny, Name == normalizedScreenName)
         - If found, add to deletion list
    5. If deletion list is empty, return error (no deny entries found)
    6. Call FeedbagService.DeleteItem() with all items in deletion list
    7. Return empty response (success) or error

### Phase 6: Integration and Testing

- [ ] **6.1** Add command cases to RecvClientCmd switch
  - Add all 8 command cases to switch statement in cmd_client.go
  - Ensure proper ordering (TOC2 commands together)

- [ ] **6.2** Add rate limiting checks
  - Determine appropriate rate limit foodgroup/subgroup for each command
  - Use checkRateLimit() helper
  - Reference existing commands for appropriate limits

- [ ] **6.3** Error handling
  - Ensure all errors return runtimeErr() format
  - Handle edge cases (empty args, invalid screen names, etc.)
  - Validate group names (non-empty, etc.)

- [ ] **6.4** Test with TOC2 client
  - Verify each command works end-to-end
  - Test error cases
  - Verify feedbag state is correctly updated
  - Verify NEW_BUDDY_REPLY2 responses are sent correctly

- [ ] **6.5** Code review and cleanup
  - Remove debug prints
  - Add/update function documentation
  - Ensure consistent error messages
  - Check for code duplication and refactor if needed

## Technical Notes

### FeedbagItem Structure
- `ClassID`: FeedbagClassIdBuddy (0x0000), FeedbagClassIdGroup (0x0001), FeedbagClassIDPermit (0x0002), FeedbagClassIDDeny (0x0003)
- `ItemID`: Unique identifier for the item
- `GroupID`: For buddies, this is the group they belong to. For groups, this is 0. For permit/deny, this is 0.
- `Name`: Screen name (for buddies/permit/deny) or group name (for groups)
- `TLVLBlock`: TLV attributes (e.g., order, alias, note)

### Key Differences from TOC 1
- TOC 1 uses BuddyService and PermitDenyService (SNAC-based)
- TOC 2 uses FeedbagService (feedbag-based, persistent)
- TOC 2 has group management (create/delete groups)
- TOC 2 has remove permit/deny commands
- TOC 2 automatically saves to config (no separate save step)

### Rate Limiting
- Reference existing commands for appropriate rate limits
- Buddy operations: wire.Buddy, wire.BuddyAddBuddies / wire.BuddyDelBuddies
- Permit/Deny operations: wire.PermitDeny, wire.PermitDenyAddPermListEntries / wire.PermitDenyAddDenyListEntries
- Feedbag operations: wire.Feedbag, wire.FeedbagInsertItem / wire.FeedbagDeleteItem

### Screen Name Normalization
Screen names are normalized using `state.NewIdentScreenName()` which:
- Removes all spaces: `strings.ReplaceAll(screenName, " ", "")`
- Converts to lowercase: `strings.ToLower(str)`

Usage: `state.NewIdentScreenName(screenName).String()` to get the normalized string.

### Config Format Parsing
The TOC2 config format is:
```
{g:group<lf>b:buddy1<lf>b:buddy2<lf>}
```

Where `<lf>` is a linefeed character (ASCII 10, `\n`).

Extended format for buddies with alias/note:
```
b:buddy:alias:::::note
```

All screen names in the config should be normalized before storing in feedbag.

## References
- TOC2 spec: https://github.com/nelhage/snb/blob/93fea36bd44ac8bc6c7ea4e9fd1055480236507d/TOC2.txt
- Existing TOC 1 handlers: server/toc/cmd_client.go
- FeedbagService: foodgroup/feedbag.go
- Management API examples: server/http/mgmt_api.go (lines 1294-1564)
- FeedbagItem structure: wire/snacs.go
