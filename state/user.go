package state

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// ErrDupUser indicates that a user already exists.
	ErrDupUser = errors.New("user already exists")
	// ErrNoUser indicates that a user does not exist.
	ErrNoUser = errors.New("user does not exist")
	// ErrNoEmailAddress indicates that a user has not set an email address.
	ErrNoEmailAddress = errors.New("user has no email address")
)

// IdentScreenName struct stores the normalized version of a user's screen name.
// This format is used for uniformity in storage and comparison by removing spaces
// and converting all characters to lowercase.
type IdentScreenName struct {
	// screenName contains the identifier screen name value. Do not assign this
	// value directly. Rather, set it through NewIdentScreenName. This ensures
	// that when an instance of IdentScreenName is present, it's guaranteed to
	// have a normalized value.
	screenName string
}

// String returns the string representation of the IdentScreenName.
func (i IdentScreenName) String() string {
	return i.screenName
}

// UIN returns a numeric UIN representation of the IdentScreenName.
func (i IdentScreenName) UIN() uint32 {
	v, _ := strconv.Atoi(i.screenName)
	return uint32(v)
}

// NewIdentScreenName creates a new IdentScreenName.
func NewIdentScreenName(screenName string) IdentScreenName {
	str := strings.ReplaceAll(screenName, " ", "")
	str = strings.ToLower(str)
	return IdentScreenName{screenName: str}
}

// DisplayScreenName type represents the screen name in the user-defined format.
// This includes the original casing and spacing as defined by the user.
type DisplayScreenName string

var (
	ErrAIMHandleInvalidFormat = errors.New("screen name must start with a letter, cannot end with a space, and must contain only letters, numbers, and spaces")
	ErrAIMHandleLength        = errors.New("screen name must be between 3 and 16 characters")
	ErrPasswordInvalid        = errors.New("invalid password length")
	ErrICQUINInvalidFormat    = errors.New("uin must be a number in the range 10000-2147483646")
)

// ValidateAIMHandle returns an error if the instance is not a valid AIM screen name.
// Possible errors:
//   - ErrAIMHandleLength: if the screen name has less than 3 non-space
//     characters or more than 16 characters (including spaces).
//   - ErrAIMHandleInvalidFormat: if the screen name does not start with a
//     letter, ends with a space, or contains invalid characters
func (s DisplayScreenName) ValidateAIMHandle() error {
	if len(s) > 16 {
		return ErrAIMHandleLength
	}

	c := 0
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			c++
		case r != ' ':
			return ErrAIMHandleInvalidFormat
		}
	}
	if c < 3 {
		return ErrAIMHandleLength
	}

	// Must start with a letter, cannot end with a space, and must contain only
	// letters, numbers, and spaces.
	if !unicode.IsLetter(rune(s[0])) || s[len(s)-1] == ' ' {
		return ErrAIMHandleInvalidFormat
	}

	return nil
}

// IsUIN indicates whether the screen name is an ICQ UIN.
func (s DisplayScreenName) IsUIN() bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// ValidateUIN returns an error if the instance is not a valid ICQ UIN.
// Possible errors:
//   - ErrICQUINInvalidFormat: if the UIN is not a number or is not in the valid
//     range
func (s DisplayScreenName) ValidateUIN() error {
	uin, err := strconv.Atoi(string(s))
	if err != nil || uin < 10000 || uin > 2147483646 {
		return ErrICQUINInvalidFormat
	}
	return nil
}

// IdentScreenName converts the DisplayScreenName to an IdentScreenName by applying
// the normalization process defined in NewIdentScreenName.
func (s DisplayScreenName) IdentScreenName() IdentScreenName {
	return NewIdentScreenName(string(s))
}

// String returns the original display string of the screen name, preserving the user-defined
// casing and spaces.
func (s DisplayScreenName) String() string {
	return string(s)
}

// User represents a user account.
type User struct {
	// IdentScreenName is the AIM screen name.
	IdentScreenName IdentScreenName
	// DisplayScreenName is the formatted screen name.
	DisplayScreenName DisplayScreenName
	// AuthKey is the salt for the MD5 password hash.
	AuthKey string
	// StrongMD5Pass is the MD5 password hash format used by AIM v4.8-v5.9.
	StrongMD5Pass []byte
	// WeakMD5Pass is the MD5 password hash format used by AIM v3.5-v4.7. This
	// hash is used to authenticate roasted passwords for AIM v1.0-v3.0.
	WeakMD5Pass []byte
	// IsICQ indicates whether the user is an ICQ account (true) or an AIM
	// account (false).
	IsICQ bool
	// ConfirmStatus indicates whether the user has confirmed their AIM account.
	ConfirmStatus bool
	// RegStatus is the AIM registration status.
	//  1: no disclosure
	//  2: limit disclosure
	//  3: full disclosure
	RegStatus int
	// SuspendedStatus is the account suspended status
	SuspendedStatus uint16
	// EmailAddress is the email address set by the AIM client.
	EmailAddress string
	// ICQAffiliations holds information about the user's affiliations,
	// including past and current affiliations.
	ICQAffiliations ICQAffiliations
	// ICQInterests holds information about the user's interests, categorized
	// by code and associated keywords.
	ICQInterests ICQInterests
	// ICQMoreInfo contains additional information about the user.
	ICQMoreInfo ICQMoreInfo
	// ICQPermissions specifies the user's privacy settings.
	ICQPermissions ICQPermissions
	// ICQBasicInfo contains the user's basic profile information, including
	// contact details and personal identifiers.
	ICQBasicInfo ICQBasicInfo
	// ICQNotes allows the user to store personal notes or additional
	// information within their profile.
	ICQNotes ICQUserNotes
	// ICQWorkInfo contains the user's professional information, including
	// their workplace address and job-related details.
	ICQWorkInfo      ICQWorkInfo
	AIMDirectoryInfo AIMNameAndAddr
	// TOCConfig is the user's saved server-side info (buddy list, etc) for
	// on the TOC service.
	TOCConfig string
	// IsBot indicates whether the user is a bot.
	IsBot bool
	// LastWarnUpdate is the timestamp when the user's warning level was last updated.
	LastWarnUpdate time.Time
	// LastWarnLevel is the warning level when the user last signed off.
	LastWarnLevel uint16
	// OfflineMsgCount is the count of offline messages for the user.
	OfflineMsgCount int
}

// UserProfile represents a user's profile information.
type UserProfile struct {
	// ProfileText is the free-form profile body content.
	ProfileText string
	// MIMEType is the MIME type of the profile content.
	MIMEType string
	// UpdateTime is when the profile was last updated.
	UpdateTime time.Time
}

// IsZero returns true if the profile has not been set.
func (p UserProfile) IsZero() bool {
	return p.UpdateTime.IsZero()
}

// IsEmpty returns true of the profile is empty (including not set).
func (p UserProfile) IsEmpty() bool {
	return p.IsZero() || p.ProfileText == "" || p.ProfileText == "\x00"
}

// AIMNameAndAddr holds name and address AIM directory information.
type AIMNameAndAddr struct {
	// FirstName is the user's first name.
	FirstName string
	// LastName is the user's last name.
	LastName string
	// MiddleName is the user's middle name.
	MiddleName string
	// MaidenName is the user's maiden name.
	MaidenName string
	// Country is the user's country of residence.
	Country string
	// State is the user's state or region of residence.
	State string
	// City is the user's city of residence.
	City string
	// NickName is the user's chosen nickname.
	NickName string
	// ZIPCode is the user's postal or ZIP code.
	ZIPCode string
	// Address is the user's street address.
	Address string
}

// ICQBasicInfo holds basic information about an ICQ user, including their name, contact details, and location.
type ICQBasicInfo struct {
	// Address is the user's residential address.
	Address string
	// CellPhone is the user's mobile phone number.
	CellPhone string
	// City is the city where the user resides.
	City string
	// CountryCode is the code representing the user's country of residence.
	CountryCode uint16
	// EmailAddress is the user's primary email address.
	EmailAddress string
	// Fax is the user's fax number.
	Fax string
	// FirstName is the user's first name.
	FirstName string
	// GMTOffset is the user's time zone offset from GMT.
	GMTOffset uint8
	// LastName is the user's last name.
	LastName string
	// Nickname is the user's nickname or preferred name.
	Nickname string
	// Phone is the user's landline phone number.
	Phone string
	// PublishEmail indicates whether the user's email address is public.
	PublishEmail bool
	// State is the state or region where the user resides.
	State string
	// ZIPCode is the user's postal code.
	ZIPCode string
}

// ICQAffiliations contains information about the user's affiliations, both past and present.
type ICQAffiliations struct {
	// PastCode1 is the code representing the user's first past affiliation.
	PastCode1 uint16
	// PastKeyword1 is the keyword associated with the user's first past affiliation.
	PastKeyword1 string
	// PastCode2 is the code representing the user's second past affiliation.
	PastCode2 uint16
	// PastKeyword2 is the keyword associated with the user's second past affiliation.
	PastKeyword2 string
	// PastCode3 is the code representing the user's third past affiliation.
	PastCode3 uint16
	// PastKeyword3 is the keyword associated with the user's third past affiliation.
	PastKeyword3 string
	// CurrentCode1 is the code representing the user's current first affiliation.
	CurrentCode1 uint16
	// CurrentKeyword1 is the keyword associated with the user's current first affiliation.
	CurrentKeyword1 string
	// CurrentCode2 is the code representing the user's current second affiliation.
	CurrentCode2 uint16
	// CurrentKeyword2 is the keyword associated with the user's current second affiliation.
	CurrentKeyword2 string
	// CurrentCode3 is the code representing the user's current third affiliation.
	CurrentCode3 uint16
	// CurrentKeyword3 is the keyword associated with the user's current third affiliation.
	CurrentKeyword3 string
}

// ICQInterests holds information about the user's interests, categorized by
// interest code and associated keyword.
type ICQInterests struct {
	// Code1 is the code representing the user's first interest.
	Code1 uint16
	// Keyword1 is the keyword associated with the user's first interest.
	Keyword1 string
	// Code2 is the code representing the user's second interest.
	Code2 uint16
	// Keyword2 is the keyword associated with the user's second interest.
	Keyword2 string
	// Code3 is the code representing the user's third interest.
	Code3 uint16
	// Keyword3 is the keyword associated with the user's third interest.
	Keyword3 string
	// Code4 is the code representing the user's fourth interest.
	Code4 uint16
	// Keyword4 is the keyword associated with the user's fourth interest.
	Keyword4 string
}

// ICQUserNotes contains personal notes or additional information added by the user.
type ICQUserNotes struct {
	// Notes are the personal notes or additional information the user has
	// entered in their profile.
	Notes string
}

// ICQMoreInfo contains additional information about the user, such as
// demographic and language preferences.
type ICQMoreInfo struct {
	// Gender is the user's gender, represented by a code.
	Gender uint16
	// HomePageAddr is the URL of the user's personal homepage.
	HomePageAddr string
	// BirthYear is the user's birth year.
	BirthYear uint16
	// BirthMonth is the user's birth month.
	BirthMonth uint8
	// BirthDay is the user's birth day.
	BirthDay uint8
	// Lang1 is the code for the user's primary language.
	Lang1 uint8
	// Lang2 is the code for the user's secondary language.
	Lang2 uint8
	// Lang3 is the code for the user's tertiary language.
	Lang3 uint8
}

// ICQWorkInfo contains information about the user's professional life,
// including their workplace and job title.
type ICQWorkInfo struct {
	// Address is the address of the user's workplace.
	Address string
	// City is the city where the user's workplace is located.
	City string
	// Company is the name of the user's employer or company.
	Company string
	// CountryCode is the code representing the country where the user's
	// workplace is located.
	CountryCode uint16
	// Department is the name of the department within the user's company.
	Department string
	// Fax is the fax number for the user's workplace.
	Fax string
	// OccupationCode is the code representing the user's occupation.
	OccupationCode uint16
	// Phone is the phone number for the user's workplace.
	Phone string
	// Position is the user's job title or position within the company.
	Position string
	// State is the state or region where the user's workplace is located.
	State string
	// WebPage is the URL of the user's company's website.
	WebPage string
	// ZIPCode is the postal code for the user's workplace.
	ZIPCode string
}

// ICQPermissions specifies the privacy settings of an ICQ user.
type ICQPermissions struct {
	// AuthRequired indicates where users must ask this permission to add them
	// to their contact list.
	AuthRequired bool
	// WebAware indicates whether the user's online status is visible via web.
	WebAware bool
	// AllowSpam indicates whether to allow messages from users not on the contact list.
	AllowSpam bool
}

// Age returns the user's age relative to their birthday and timeNow.
func (u *User) Age(timeNow func() time.Time) uint16 {
	now := timeNow().UTC()
	switch {
	case u.ICQMoreInfo.BirthYear > 0 && u.ICQMoreInfo.BirthDay == 0 && u.ICQMoreInfo.BirthMonth == 0:
		bday := time.Date(int(u.ICQMoreInfo.BirthYear), time.January, 1, 0, 0, 0, 0, time.UTC)
		return uint16(now.Year() - bday.Year())
	case u.ICQMoreInfo.BirthYear > 0 && u.ICQMoreInfo.BirthDay > 0 && u.ICQMoreInfo.BirthMonth > 0:
		bday := time.Date(int(u.ICQMoreInfo.BirthYear), time.Month(u.ICQMoreInfo.BirthMonth), int(u.ICQMoreInfo.BirthDay), 0, 0, 0, 0, time.UTC)
		years := now.Year() - bday.Year()
		if now.YearDay() < bday.YearDay() {
			years--
		}
		return uint16(years)
	default: // invalid date
		return 0
	}
}

// ValidateHash validates MD5-hashed passwords for BUCP auth. It handles
// hashes used in early AIM 4.x versions ("weak" hashes) and later AIM 4.x-5.x
// versions ("strong" hashes).
func (u *User) ValidateHash(md5Hash []byte) bool {
	return bytes.Equal(u.StrongMD5Pass, md5Hash) || bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// ValidateRoastedPass validates roasted passwords for FLAP auth.
func (u *User) ValidateRoastedPass(roastedPass []byte) bool {
	clearPass := wire.RoastOSCARPassword(roastedPass)
	md5Hash := wire.WeakMD5PasswordHash(string(clearPass), u.AuthKey)
	return bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// ValidateRoastedJavaPass validates roasted passwords for the Java AIM client FLAP auth.
func (u *User) ValidateRoastedJavaPass(roastedPass []byte) bool {
	clearPass := wire.RoastOSCARJavaPassword(roastedPass)
	md5Hash := wire.WeakMD5PasswordHash(string(clearPass), u.AuthKey)
	return bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// ValidateRoastedTOCPass validates roasted passwords for TOC auth.
func (u *User) ValidateRoastedTOCPass(roastedPass []byte) bool {
	clearPass := wire.RoastTOCPassword(roastedPass)
	md5Hash := wire.WeakMD5PasswordHash(string(clearPass), u.AuthKey)
	return bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// ValidatePlaintextPass validates plaintext passwords used in Kerberos auth.
func (u *User) ValidatePlaintextPass(plaintextPass []byte) bool {
	md5Hash := wire.WeakMD5PasswordHash(string(plaintextPass), u.AuthKey)
	return bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// ValidateRoastedKerberosPass validates roasted passwords used in Kerberos auth.
func (u *User) ValidateRoastedKerberosPass(roastedPass []byte) bool {
	clearPass := wire.RoastKerberosPassword(roastedPass)
	md5Hash := wire.WeakMD5PasswordHash(string(clearPass), u.AuthKey)
	return bytes.Equal(u.WeakMD5Pass, md5Hash)
}

// HashPassword computes MD5 hashes of the user's password. It computes both
// weak and strong variants and stores them in the struct.
func (u *User) HashPassword(passwd string) error {
	if u.IsICQ {
		if err := validateICQPassword(passwd); err != nil {
			return err
		}
	} else {
		if err := validateAIMPassword(passwd); err != nil {
			return err
		}
	}
	u.WeakMD5Pass = wire.WeakMD5PasswordHash(passwd, u.AuthKey)
	u.StrongMD5Pass = wire.StrongMD5PasswordHash(passwd, u.AuthKey)
	return nil
}

// validateAIMPassword returns an error if the AIM password is invalid.
// A valid password is 4-16 characters long. The min and max password length
// values reflect AOL's password validation rules circa 2000.
func validateAIMPassword(pass string) error {
	if len(pass) < 4 || len(pass) > 16 {
		return fmt.Errorf("%w: password length must be between 4-16 characters", ErrPasswordInvalid)
	}
	return nil
}

// validateICQPassword returns an error if the ICQ password is invalid.
// A valid password is 6-8 characters long. It's unclear what min length the
// ICQ service required, so a plausible minimum value is set. The max length
// reflects the password limitation imposed by old ICQ clients.
func validateICQPassword(pass string) error {
	if len(pass) < 6 || len(pass) > 8 {
		return fmt.Errorf("%w: password must be between 6-8 characters", ErrPasswordInvalid)
	}
	return nil
}

type OfflineMessage struct {
	Sender    IdentScreenName
	Recipient IdentScreenName
	Message   wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	Sent      time.Time
}

// Category represents an AIM directory category.
type Category struct {
	// ID is the category ID
	ID uint8
	// Name is the category name
	Name string `oscar:"len_prefix=uint16"`
}

// Keyword represents an AIM directory keyword.
type Keyword struct {
	// ID is the keyword ID
	ID uint8
	// Name is the keyword name
	Name string `oscar:"len_prefix=uint16"`
}
