package wire

// ICQ Legacy Protocol Command Constants
// Ported from iserverd v3_defines.h and v5_defines.h

// Protocol version identifiers
const (
	ICQLegacyVersionV2 uint16 = 0x0002
	ICQLegacyVersionV3 uint16 = 0x0003
	ICQLegacyVersionV4 uint16 = 0x0004
	ICQLegacyVersionV5 uint16 = 0x0005
)

// Client Commands (received from client)
const (
	// Common commands (V2-V5)
	ICQLegacyCmdAck            uint16 = 0x000A // Acknowledgment
	ICQLegacyCmdThruServer     uint16 = 0x010E // Send message through server
	ICQLegacyCmdReconnect      uint16 = 0x015E // Reconnect request
	ICQLegacyCmdLogin          uint16 = 0x03E8 // Login request
	ICQLegacyCmdGetDeps        uint16 = 0x03F2 // Pre-auth pseudo-login (historically "get departments list")
	ICQLegacyCmdContactList    uint16 = 0x0406 // Send contact list
	ICQLegacyCmdSearchUIN      uint16 = 0x041A // Search by UIN (old)
	ICQLegacyCmdSearchUser     uint16 = 0x0424 // Search by name/email (old)
	ICQLegacyCmdKeepAlive      uint16 = 0x042E // Keep connection alive (ping)
	ICQLegacyCmdLogoff         uint16 = 0x0438 // Disconnect
	ICQLegacyCmdSysMsgDoneAck  uint16 = 0x0442 // Offline messages acknowledged
	ICQLegacyCmdSysMsgReq      uint16 = 0x044C // Request offline messages
	ICQLegacyCmdAuthorize      uint16 = 0x0456 // Authorize user (V2)
	ICQLegacyCmdInfoReq        uint16 = 0x0460 // Get user info (old)
	ICQLegacyCmdExtInfoReq     uint16 = 0x046A // Get extended info (old)
	ICQLegacyCmdSetPassword    uint16 = 0x049C // Change password
	ICQLegacyCmdUpdateBasic    uint16 = 0x04A6 // Update basic profile (V2)
	ICQLegacyCmdUpdateDetail   uint16 = 0x04B0 // Update extended profile (V2)
	ICQLegacyCmdGetExternals   uint16 = 0x04C4 // Get external services
	ICQLegacyCmdLoginInfoReq   uint16 = 0x04CE // Login info request (V4)
	ICQLegacyCmdSetStatus      uint16 = 0x04D8 // Change status
	ICQLegacyCmdFirstLogin     uint16 = 0x04EC // Initial login setup
	ICQLegacyCmdSetBasicInfo   uint16 = 0x050A // Update basic profile (V4+)
	ICQLegacyCmdSetAuth        uint16 = 0x0514 // Set authorization mode
	ICQLegacyCmdKeepAlive2     uint16 = 0x051E // Alternate keep-alive
	ICQLegacyCmdUserAdd        uint16 = 0x053C // Add user to contacts
	ICQLegacyCmdSearchStart    uint16 = 0x05C8 // Begin user search
	ICQLegacyCmdGetDeps1       uint16 = 0x05F0 // Pre-auth pseudo-login (alternate)
	ICQLegacyCmdUserGetInfo    uint16 = 0x05FA // Get user info
	ICQLegacyCmdBroadcastAll   uint16 = 0x060E // Broadcast to all users
	ICQLegacyCmdBroadcastOnl   uint16 = 0x0618 // Broadcast to online users
	ICQLegacyCmdWWPMsg         uint16 = 0x0622 // Web pager message
	ICQLegacyCmdInvisibleList  uint16 = 0x06A4 // Set invisible list
	ICQLegacyCmdVisibleList    uint16 = 0x06AE // Set visible list
	ICQLegacyCmdRegNewUser     uint16 = 0x03FC // Register new user (V5)
	ICQLegacyCmdRegRequestInfo uint16 = 0x05DC // Request registration info (V3/V4)
	ICQLegacyCmdRegNewUserInfo uint16 = 0x05E6 // Send registration form (V3/V4)

	// V5-specific commands
	ICQLegacyCmdMetaUser       uint16 = 0x064A // Meta user commands
	ICQLegacyCmdChangeVILists  uint16 = 0x06B8 // Change visible/invisible lists
)

// Server Responses (sent to client)
const (
	ICQLegacySrvAck            uint16 = 0x000A // Acknowledgment
	ICQLegacySrvUserLMeta      uint16 = 0x001E // User last meta
	ICQLegacySrvSetOffline     uint16 = 0x0028 // Force offline
	ICQLegacySrvUserDepsList   uint16 = 0x0032 // Pre-auth response (historically "departments list")
	ICQLegacySrvUserDepsList1  uint16 = 0x0082 // Pre-auth response (session) - from v3_send_depslist1()
	ICQLegacySrvNewUIN         uint16 = 0x0046 // New UIN assigned
	ICQLegacySrvHello          uint16 = 0x005A // Login successful
	ICQLegacySrvWrongPasswd    uint16 = 0x0064 // Invalid password
	ICQLegacySrvUserOnline     uint16 = 0x006E // Contact came online
	ICQLegacySrvUserOffline    uint16 = 0x0078 // Contact went offline
	ICQLegacySrvSearchFound    uint16 = 0x008C // Search result (old)
	ICQLegacySrvSearchDone     uint16 = 0x00A0 // Search complete (old)
	ICQLegacySrvUpdatedBasic   uint16 = 0x00B4 // Basic info updated successfully (V2)
	ICQLegacySrvUpdateBasicFail uint16 = 0x00BE // Basic info update failed (V2)
	ICQLegacySrvUpdatedDetail  uint16 = 0x00C8 // Detail info updated successfully (V2)
	ICQLegacySrvUpdateDetailFail uint16 = 0x00D2 // Detail info update failed (V2)
	ICQLegacySrvUpdatedBasicV4   uint16 = 0x01E0 // Basic info updated successfully (V4)
	ICQLegacySrvUpdateBasicFailV4 uint16 = 0x01EA // Basic info update failed (V4)
	ICQLegacySrvSysMsgOffline  uint16 = 0x00DC // Offline message
	ICQLegacySrvSysMsgDone     uint16 = 0x00E6 // End of offline messages
	ICQLegacySrvNotConnected   uint16 = 0x00F0 // Not connected error
	ICQLegacySrvBusy           uint16 = 0x00FA // Server busy
	ICQLegacySrvSysMsgOnline   uint16 = 0x0104 // Online message
	ICQLegacySrvInfoReply      uint16 = 0x0118 // User info response (single)
	ICQLegacySrvExtInfoReply   uint16 = 0x0122 // Extended info response
	ICQLegacySrvInvalidUIN     uint16 = 0x012C // Invalid UIN
	ICQLegacySrvUserStatus     uint16 = 0x01A4 // Status changed
	ICQLegacySrvUserListDone   uint16 = 0x021C // Contact list processed
	ICQLegacySrvUserInfoBasic  uint16 = 0x02E4 // Basic user info (nick, first, last, email, auth) - from v3_defines.h ICQ_CMDxSND_USERxINFO_BASIC
	ICQLegacySrvUserInfoWork   uint16 = 0x02F8 // Work info - from v3_defines.h ICQ_CMDxSND_USERxINFO_WORK
	ICQLegacySrvUserInfoWWeb   uint16 = 0x030C // Work web page - from v3_defines.h ICQ_CMDxSND_USERxINFO_WWEB
	ICQLegacySrvUserInfoHome   uint16 = 0x0320 // Home info - from v3_defines.h ICQ_CMDxSND_USERxINFO_HOME
	ICQLegacySrvUserInfoHWeb   uint16 = 0x0334 // Home web page - from v3_defines.h ICQ_CMDxSND_USERxINFO_HWEB
	ICQLegacySrvRegisterInfo   uint16 = 0x037A // Registration info (admin notes)
	ICQLegacySrvLoginErr       uint16 = 0x0370 // Login error
	ICQLegacySrvRegistrationOK uint16 = 0x0384 // Registration successful with new UIN
	ICQLegacySrvMetaUser       uint16 = 0x03DE // Meta user response
	ICQLegacySrvAckNewUIN      uint16 = 0x03FC // Registration successful
)

// META_USER Sub-Commands (V5)
const (
	// Set commands
	ICQLegacyMetaSetBasic        uint16 = 0x03E8 // Set basic info
	ICQLegacyMetaSetBasic2       uint16 = 0x03E9 // Set basic info (alt)
	ICQLegacyMetaSetWork         uint16 = 0x03F2 // Set work info
	ICQLegacyMetaSetWork2        uint16 = 0x03F3 // Set work info (alt)
	ICQLegacyMetaSetMore         uint16 = 0x03FC // Set more info
	ICQLegacyMetaSetMore2        uint16 = 0x03FD // Set more info (alt)
	ICQLegacyMetaSetAbout        uint16 = 0x0406 // Set about text
	ICQLegacyMetaSetInterests    uint16 = 0x0410 // Set interests
	ICQLegacyMetaSetAffiliations uint16 = 0x041A // Set affiliations
	ICQLegacyMetaSetSecurity     uint16 = 0x0424 // Set security options
	ICQLegacyMetaSetPass         uint16 = 0x042E // Change password
	ICQLegacyMetaSetHPCat        uint16 = 0x0442 // Set homepage category

	// Get commands
	ICQLegacyMetaUserFullInfo  uint16 = 0x04B0 // Request full user info
	ICQLegacyMetaUserFullInfo2 uint16 = 0x04B1 // Request full user info (alt)
	ICQLegacyMetaUserInfo      uint16 = 0x04BA // Request short user info
	ICQLegacyMetaUserUnreg     uint16 = 0x04C4 // Unregister account
	ICQLegacyMetaLoginInfo     uint16 = 0x04CE // Login info
	ICQLegacyMetaLoginInfo2    uint16 = 0x04CF // Login info (alt)

	// Search commands
	ICQLegacyMetaSearchName   uint16 = 0x0514 // Search by name
	ICQLegacyMetaSearchName2  uint16 = 0x0515 // Search by name (alt)
	ICQLegacyMetaSearchUIN    uint16 = 0x051E // Search by UIN
	ICQLegacyMetaSearchUIN2   uint16 = 0x051F // Search by UIN (alt)
	ICQLegacyMetaSearchEmail  uint16 = 0x0528 // Search by email
	ICQLegacyMetaSearchEmail2 uint16 = 0x0529 // Search by email (alt)
	ICQLegacyMetaSearchWhite  uint16 = 0x0532 // White pages search
	ICQLegacyMetaSearchWhite2 uint16 = 0x0533 // White pages search (alt)

	// Other
	ICQLegacyMetaUsageStats uint16 = 0x06B8 // Usage statistics
	ICQLegacyMetaLogin      uint16 = 0x07D0 // Meta login
)

// META_USER Server Response Sub-Commands
const (
	ICQLegacySrvMetaSetBasicAck     uint16 = 0x0064 // Set basic ack
	ICQLegacySrvMetaSetWorkAck      uint16 = 0x006E // Set work ack
	ICQLegacySrvMetaSetMoreAck      uint16 = 0x0078 // Set more ack
	ICQLegacySrvMetaSetAboutAck     uint16 = 0x0082 // Set about ack
	ICQLegacySrvMetaSetInterestsAck uint16 = 0x008C // Set interests ack
	ICQLegacySrvMetaSetAffilAck     uint16 = 0x0096 // Set affiliations ack
	ICQLegacySrvMetaSetSecureAck    uint16 = 0x00A0 // Set security ack
	ICQLegacySrvMetaSetPassAck      uint16 = 0x00AA // Set password ack
	ICQLegacySrvMetaUnregAck        uint16 = 0x00B4 // Unregister ack
	ICQLegacySrvMetaSetHPCatAck     uint16 = 0x00BE // Set homepage cat ack
	ICQLegacySrvMetaUserInfo2       uint16 = 0x00C8 // User info response
	ICQLegacySrvMetaInfoWork        uint16 = 0x00D2 // Work info response
	ICQLegacySrvMetaInfoMore        uint16 = 0x00DC // More info response
	ICQLegacySrvMetaInfoAbout       uint16 = 0x00E6 // About response
	ICQLegacySrvMetaInfoInterests   uint16 = 0x00F0 // Interests response
	ICQLegacySrvMetaInfoAffil       uint16 = 0x00FA // Affiliations response
	ICQLegacySrvMetaUserInfo        uint16 = 0x0104 // Short user info
	ICQLegacySrvMetaInfoHPCat       uint16 = 0x010E // Homepage category
	ICQLegacySrvMetaUserFound       uint16 = 0x0190 // Search result
	ICQLegacySrvMetaUserLastFound   uint16 = 0x019A // Last search result
	ICQLegacySrvMetaWhiteFound      uint16 = 0x01A4 // White pages result
	ICQLegacySrvMetaWhiteLastFound  uint16 = 0x01AE // Last white pages result
)

// Message Types
const (
	ICQLegacyMsgText       uint16 = 0x0001 // Plain text message
	ICQLegacyMsgChat       uint16 = 0x0002 // Chat request
	ICQLegacyMsgFile       uint16 = 0x0003 // File transfer request
	ICQLegacyMsgURL        uint16 = 0x0004 // URL with description
	ICQLegacyMsgAuthReq    uint16 = 0x0006 // Authorization request
	ICQLegacyMsgAuthDeny   uint16 = 0x0007 // Authorization denied
	ICQLegacyMsgAuthGrant  uint16 = 0x0008 // Authorization granted
	ICQLegacyMsgServer     uint16 = 0x0009 // Server message
	ICQLegacyMsgAdded      uint16 = 0x000C // "You were added" notification
	ICQLegacyMsgWWP        uint16 = 0x000D // Web pager message
	ICQLegacyMsgEmailPager uint16 = 0x000E // Email pager message
	ICQLegacyMsgContacts   uint16 = 0x0013 // Contact list sharing
	ICQLegacyMsgPlugin     uint16 = 0x001A // Plugin message
	ICQLegacyMsgAutoAway   uint16 = 0x00E8 // Auto-away message
	ICQLegacyMsgAutoOcc    uint16 = 0x00E9 // Auto-occupied message
	ICQLegacyMsgAutoNA     uint16 = 0x00EA // Auto-NA message
	ICQLegacyMsgAutoDND    uint16 = 0x00EB // Auto-DND message
	ICQLegacyMsgAutoFFC    uint16 = 0x00EC // Auto-FFC message
)

// User Status Codes
const (
	ICQLegacyStatusOnline    uint32 = 0x00000000 // Available
	ICQLegacyStatusAway      uint32 = 0x00000001 // Away from computer
	ICQLegacyStatusDND       uint32 = 0x00000002 // Do not disturb
	ICQLegacyStatusNA        uint32 = 0x00000004 // Not available
	ICQLegacyStatusOccupied  uint32 = 0x00000010 // Busy/Occupied
	ICQLegacyStatusFFC       uint32 = 0x00000020 // Free for chat
	ICQLegacyStatusInvisible uint32 = 0x00000100 // Hidden from others
)

// Status Flags (can be combined with status)
const (
	ICQLegacyStatusFlagWebAware uint32 = 0x00010000 // Web aware
	ICQLegacyStatusFlagShowIP   uint32 = 0x00020000 // Show IP address
	ICQLegacyStatusFlagBirthday uint32 = 0x00080000 // Birthday flag
	ICQLegacyStatusFlagWebFront uint32 = 0x00200000 // Web front
	ICQLegacyStatusFlagDCAuth   uint32 = 0x10000000 // DC requires auth
	ICQLegacyStatusFlagDCCont   uint32 = 0x20000000 // DC only contacts
)

// Login Error Codes
const (
	ICQLegacyLoginErrSuccess       uint8 = 0x00 // Success
	ICQLegacyLoginErrBadPassword   uint8 = 0x01 // Invalid password
	ICQLegacyLoginErrBadUIN        uint8 = 0x02 // Invalid UIN
	ICQLegacyLoginErrNotRegistered uint8 = 0x03 // UIN not registered
	ICQLegacyLoginErrBusy          uint8 = 0x04 // Server busy
	ICQLegacyLoginErrRateLimit     uint8 = 0x05 // Rate limited
	ICQLegacyLoginErrOldVersion    uint8 = 0x06 // Client too old
	ICQLegacyLoginErrDualLogin     uint8 = 0x07 // Already logged in
	ICQLegacyLoginErrTryAgain      uint8 = 0x08 // Try again later
)

// Search Result Codes
const (
	ICQLegacySearchSuccess   uint8 = 0x00 // Search successful
	ICQLegacySearchNotFound  uint8 = 0x01 // No results found
	ICQLegacySearchTooMany   uint8 = 0x02 // Too many results
	ICQLegacySearchError     uint8 = 0x03 // Search error
)

// Authorization Modes
const (
	ICQLegacyAuthNone     uint8 = 0x00 // No authorization required
	ICQLegacyAuthRequired uint8 = 0x01 // Authorization required
)

// Gender Codes
const (
	ICQLegacyGenderUnspecified uint8 = 0x00
	ICQLegacyGenderFemale      uint8 = 0x01
	ICQLegacyGenderMale        uint8 = 0x02
)
