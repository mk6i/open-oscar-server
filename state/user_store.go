package state

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratesqlite "github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/httpfs"
	"modernc.org/sqlite"
	lib "modernc.org/sqlite/lib"

	"github.com/mk6i/retro-aim-server/wire"
)

const offlineInboxLimit = 10

var (
	ErrKeywordCategoryExists   = errors.New("keyword category already exists")
	ErrKeywordCategoryNotFound = errors.New("keyword category not found")
	ErrBARTItemExists          = errors.New("BART asset already exists")
	ErrBARTItemNotFound        = errors.New("BART asset not found")
	ErrKeywordExists           = errors.New("keyword already exists")
	ErrKeywordInUse            = errors.New("can't delete keyword that is associated with a user")
	ErrKeywordNotFound         = errors.New("keyword not found")
	ErrOfflineInboxFull        = errors.New("offline inbox full")
	errTooManyCategories       = errors.New("there are too many keyword categories")
	errTooManyKeywords         = errors.New("there are too many keywords")
)

//go:embed migrations/*
var migrations embed.FS

// SQLiteUserStore stores user feedbag (buddy list), profile, and
// authentication credentials information in a SQLite database.
type SQLiteUserStore struct {
	db *sql.DB
}

// NewSQLiteUserStore creates a new instance of SQLiteUserStore. If the
// database does not already exist, a new one is created with the required
// schema.
func NewSQLiteUserStore(dbFilePath string) (*SQLiteUserStore, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=foreign_keys=on", dbFilePath))
	if err != nil {
		return nil, err
	}

	// Set the maximum number of open connections to 1.
	// This is crucial to prevent SQLITE_BUSY errors, which occur when the database
	// is locked due to concurrent access. By limiting the number of open connections
	// to 1, we ensure that all database operations are serialized, thus avoiding
	// any potential locking issues.
	db.SetMaxOpenConns(1)

	store := &SQLiteUserStore{db: db}

	if err := store.runMigrations(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return store, nil
}

func (f SQLiteUserStore) runMigrations() error {
	migrationFS, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return fmt.Errorf("failed to prepare migration subdirectory: %v", err)
	}

	sourceInstance, err := httpfs.New(http.FS(migrationFS), ".")
	if err != nil {
		return fmt.Errorf("failed to create source instance from embedded filesystem: %v", err)
	}

	driver, err := migratesqlite.WithInstance(f.db, &migratesqlite.Config{})
	if err != nil {
		return fmt.Errorf("cannot create database driver: %v", err)
	}

	m, err := migrate.NewWithInstance("httpfs", sourceInstance, "sqlite", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %v", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run migrations: %v", err)
	}

	return nil
}

func (f SQLiteUserStore) AllUsers(ctx context.Context) ([]User, error) {
	q := `SELECT identScreenName, displayScreenName, isICQ, isBot FROM users`
	rows, err := f.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var identSN, displaySN string
		var isICQ, isBot bool
		if err := rows.Scan(&identSN, &displaySN, &isICQ, &isBot); err != nil {
			return nil, err
		}
		users = append(users, User{
			IdentScreenName:   NewIdentScreenName(identSN),
			DisplayScreenName: DisplayScreenName(displaySN),
			IsICQ:             isICQ,
			IsBot:             isBot,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (f SQLiteUserStore) FindByUIN(ctx context.Context, UIN uint32) (User, error) {
	users, err := f.queryUsers(ctx, `identScreenName = ?`, []any{strconv.Itoa(int(UIN))})
	if err != nil {
		return User{}, fmt.Errorf("FindByUIN: %w", err)
	}

	if len(users) == 0 {
		return User{}, ErrNoUser
	}

	return users[0], nil
}

func (f SQLiteUserStore) FindByICQEmail(ctx context.Context, email string) (User, error) {
	users, err := f.queryUsers(ctx, `icq_basicInfo_emailAddress = ?`, []any{email})
	if err != nil {
		return User{}, fmt.Errorf("FindByICQEmail: %w", err)
	}

	if len(users) == 0 {
		return User{}, ErrNoUser
	}

	return users[0], nil
}

func (f SQLiteUserStore) FindByAIMEmail(ctx context.Context, email string) (User, error) {
	users, err := f.queryUsers(ctx, `emailAddress = ?`, []any{email})
	if err != nil {
		return User{}, fmt.Errorf("FindByAIMEmail: %w", err)
	}

	if len(users) == 0 {
		return User{}, ErrNoUser
	}

	return users[0], nil
}

func (f SQLiteUserStore) FindByAIMKeyword(ctx context.Context, keyword string) ([]User, error) {
	where := `
		(SELECT id FROM aimKeyword WHERE name = ?) IN
		(aim_keyword1, aim_keyword2, aim_keyword3, aim_keyword4, aim_keyword5)
	`
	users, err := f.queryUsers(ctx, where, []any{keyword})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (f SQLiteUserStore) FindByICQName(ctx context.Context, firstName, lastName, nickName string) ([]User, error) {
	var args []any
	var clauses []string

	if firstName != "" {
		args = append(args, firstName)
		clauses = append(clauses, `LOWER(icq_basicInfo_firstName) = LOWER(?)`)
	}

	if lastName != "" {
		args = append(args, lastName)
		clauses = append(clauses, `LOWER(icq_basicInfo_lastName) = LOWER(?)`)
	}

	if nickName != "" {
		args = append(args, nickName)
		clauses = append(clauses, `LOWER(icq_basicInfo_nickName) = LOWER(?)`)
	}

	whereClause := strings.Join(clauses, " AND ")

	users, err := f.queryUsers(ctx, whereClause, args)
	if err != nil {
		err = fmt.Errorf("FindByICQName: %w", err)
	}

	return users, nil
}

func (f SQLiteUserStore) FindByAIMNameAndAddr(ctx context.Context, info AIMNameAndAddr) ([]User, error) {
	var args []any
	var clauses []string

	if info.FirstName != "" {
		args = append(args, info.FirstName)
		clauses = append(clauses, `LOWER(aim_firstName) = LOWER(?)`)
	}

	if info.LastName != "" {
		args = append(args, info.LastName)
		clauses = append(clauses, `LOWER(aim_lastName) = LOWER(?)`)
	}

	if info.MiddleName != "" {
		args = append(args, info.MiddleName)
		clauses = append(clauses, `LOWER(aim_middleName) = LOWER(?)`)
	}

	if info.MaidenName != "" {
		args = append(args, info.MaidenName)
		clauses = append(clauses, `LOWER(aim_maidenName) = LOWER(?)`)
	}

	if info.Country != "" {
		args = append(args, info.Country)
		clauses = append(clauses, `LOWER(aim_country) = LOWER(?)`)
	}

	if info.State != "" {
		args = append(args, info.State)
		clauses = append(clauses, `LOWER(aim_state) = LOWER(?)`)
	}

	if info.City != "" {
		args = append(args, info.City)
		clauses = append(clauses, `LOWER(aim_city) = LOWER(?)`)
	}

	if info.NickName != "" {
		args = append(args, info.NickName)
		clauses = append(clauses, `LOWER(aim_nickName) = LOWER(?)`)
	}

	if info.ZIPCode != "" {
		args = append(args, info.ZIPCode)
		clauses = append(clauses, `LOWER(aim_zipCode) = LOWER(?)`)
	}

	if info.Address != "" {
		args = append(args, info.Address)
		clauses = append(clauses, `LOWER(aim_address) = LOWER(?)`)
	}

	whereClause := strings.Join(clauses, " AND ")

	users, err := f.queryUsers(ctx, whereClause, args)
	if err != nil {
		err = fmt.Errorf("FindByAIMNameAndAddr: %w", err)
	}

	return users, nil
}

func (f SQLiteUserStore) FindByICQInterests(ctx context.Context, code uint16, keywords []string) ([]User, error) {
	var args []any
	var clauses []string

	for i := 1; i <= 4; i++ {
		var subClauses []string
		args = append(args, code)
		for _, key := range keywords {
			subClauses = append(subClauses, fmt.Sprintf("icq_interests_keyword%d LIKE ?", i))
			args = append(args, "%"+key+"%")
		}
		clauses = append(clauses, fmt.Sprintf("(icq_interests_code%d = ? AND (%s))", i, strings.Join(subClauses, " OR ")))
	}

	cond := strings.Join(clauses, " OR ")

	users, err := f.queryUsers(ctx, cond, args)
	if err != nil {
		err = fmt.Errorf("FindByICQInterests: %w", err)
	}

	return users, nil
}

func (f SQLiteUserStore) FindByICQKeyword(ctx context.Context, keyword string) ([]User, error) {
	var args []any
	var clauses []string

	for i := 1; i <= 4; i++ {
		args = append(args, "%"+keyword+"%")
		clauses = append(clauses, fmt.Sprintf("icq_interests_keyword%d LIKE ?", i))
	}

	whereClause := strings.Join(clauses, " OR ")

	users, err := f.queryUsers(ctx, whereClause, args)
	if err != nil {
		err = fmt.Errorf("FindByICQKeyword: %w", err)
	}

	return users, nil
}

func (f SQLiteUserStore) User(ctx context.Context, screenName IdentScreenName) (*User, error) {
	users, err := f.queryUsers(ctx, `identScreenName = ?`, []any{screenName.String()})
	if err != nil {
		return nil, fmt.Errorf("User: %w", err)
	}

	if len(users) == 0 {
		return nil, nil
	}

	return &users[0], nil
}

// queryUsers retrieves a list of users from the database based on the
// specified WHERE clause and query parameters. Returns a slice of User objects
// or an error if the query fails.
func (f SQLiteUserStore) queryUsers(ctx context.Context, whereClause string, queryParams []any) ([]User, error) {
	q := `
		SELECT
			identScreenName,
			displayScreenName,
			emailAddress,
			authKey,
			strongMD5Pass,
			weakMD5Pass,
			confirmStatus,
			regStatus,
			suspendedStatus,
			isBot,
			isICQ,
			icq_affiliations_currentCode1,
			icq_affiliations_currentCode2,
			icq_affiliations_currentCode3,
			icq_affiliations_currentKeyword1,
			icq_affiliations_currentKeyword2,
			icq_affiliations_currentKeyword3,
			icq_affiliations_pastCode1,
			icq_affiliations_pastCode2,
			icq_affiliations_pastCode3,
			icq_affiliations_pastKeyword1,
			icq_affiliations_pastKeyword2,
			icq_affiliations_pastKeyword3,
			icq_basicInfo_address,
			icq_basicInfo_cellPhone,
			icq_basicInfo_city,
			icq_basicInfo_countryCode,
			icq_basicInfo_emailAddress,
			icq_basicInfo_fax,
			icq_basicInfo_firstName,
			icq_basicInfo_gmtOffset,
			icq_basicInfo_lastName,
			icq_basicInfo_nickName,
			icq_basicInfo_phone,
			icq_basicInfo_publishEmail,
			icq_basicInfo_state,
			icq_basicInfo_zipCode,
			icq_interests_code1,
			icq_interests_code2,
			icq_interests_code3,
			icq_interests_code4,
			icq_interests_keyword1,
			icq_interests_keyword2,
			icq_interests_keyword3,
			icq_interests_keyword4,
			icq_moreInfo_birthDay,
			icq_moreInfo_birthMonth,
			icq_moreInfo_birthYear,
			icq_moreInfo_gender,
			icq_moreInfo_homePageAddr,
			icq_moreInfo_lang1,
			icq_moreInfo_lang2,
			icq_moreInfo_lang3,
			icq_notes,
			icq_permissions_authRequired,
			icq_workInfo_address,
			icq_workInfo_city,
			icq_workInfo_company,
			icq_workInfo_countryCode,
			icq_workInfo_department,
			icq_workInfo_fax,
			icq_workInfo_occupationCode,
			icq_workInfo_phone,
			icq_workInfo_position,
			icq_workInfo_state,
			icq_workInfo_webPage,
			icq_workInfo_zipCode,
			aim_firstName,
			aim_lastName,
			aim_middleName,
			aim_maidenName,
			aim_country,
			aim_state,
			aim_city,
			aim_nickName,
			aim_zipCode,
			aim_address,
			tocConfig,
			lastWarnUpdate,
			lastWarnLevel,
			offlineMsgCount
		FROM users
		WHERE %s
	`
	q = fmt.Sprintf(q, whereClause)
	rows, err := f.db.QueryContext(ctx, q, queryParams...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		var sn string
		var lastWarnUpdateUnix int64
		err := rows.Scan(
			&sn,
			&u.DisplayScreenName,
			&u.EmailAddress,
			&u.AuthKey,
			&u.StrongMD5Pass,
			&u.WeakMD5Pass,
			&u.ConfirmStatus,
			&u.RegStatus,
			&u.SuspendedStatus,
			&u.IsBot,
			&u.IsICQ,
			&u.ICQAffiliations.CurrentCode1,
			&u.ICQAffiliations.CurrentCode2,
			&u.ICQAffiliations.CurrentCode3,
			&u.ICQAffiliations.CurrentKeyword1,
			&u.ICQAffiliations.CurrentKeyword2,
			&u.ICQAffiliations.CurrentKeyword3,
			&u.ICQAffiliations.PastCode1,
			&u.ICQAffiliations.PastCode2,
			&u.ICQAffiliations.PastCode3,
			&u.ICQAffiliations.PastKeyword1,
			&u.ICQAffiliations.PastKeyword2,
			&u.ICQAffiliations.PastKeyword3,
			&u.ICQBasicInfo.Address,
			&u.ICQBasicInfo.CellPhone,
			&u.ICQBasicInfo.City,
			&u.ICQBasicInfo.CountryCode,
			&u.ICQBasicInfo.EmailAddress,
			&u.ICQBasicInfo.Fax,
			&u.ICQBasicInfo.FirstName,
			&u.ICQBasicInfo.GMTOffset,
			&u.ICQBasicInfo.LastName,
			&u.ICQBasicInfo.Nickname,
			&u.ICQBasicInfo.Phone,
			&u.ICQBasicInfo.PublishEmail,
			&u.ICQBasicInfo.State,
			&u.ICQBasicInfo.ZIPCode,
			&u.ICQInterests.Code1,
			&u.ICQInterests.Code2,
			&u.ICQInterests.Code3,
			&u.ICQInterests.Code4,
			&u.ICQInterests.Keyword1,
			&u.ICQInterests.Keyword2,
			&u.ICQInterests.Keyword3,
			&u.ICQInterests.Keyword4,
			&u.ICQMoreInfo.BirthDay,
			&u.ICQMoreInfo.BirthMonth,
			&u.ICQMoreInfo.BirthYear,
			&u.ICQMoreInfo.Gender,
			&u.ICQMoreInfo.HomePageAddr,
			&u.ICQMoreInfo.Lang1,
			&u.ICQMoreInfo.Lang2,
			&u.ICQMoreInfo.Lang3,
			&u.ICQNotes.Notes,
			&u.ICQPermissions.AuthRequired,
			&u.ICQWorkInfo.Address,
			&u.ICQWorkInfo.City,
			&u.ICQWorkInfo.Company,
			&u.ICQWorkInfo.CountryCode,
			&u.ICQWorkInfo.Department,
			&u.ICQWorkInfo.Fax,
			&u.ICQWorkInfo.OccupationCode,
			&u.ICQWorkInfo.Phone,
			&u.ICQWorkInfo.Position,
			&u.ICQWorkInfo.State,
			&u.ICQWorkInfo.WebPage,
			&u.ICQWorkInfo.ZIPCode,
			&u.AIMDirectoryInfo.FirstName,
			&u.AIMDirectoryInfo.LastName,
			&u.AIMDirectoryInfo.MiddleName,
			&u.AIMDirectoryInfo.MaidenName,
			&u.AIMDirectoryInfo.Country,
			&u.AIMDirectoryInfo.State,
			&u.AIMDirectoryInfo.City,
			&u.AIMDirectoryInfo.NickName,
			&u.AIMDirectoryInfo.ZIPCode,
			&u.AIMDirectoryInfo.Address,
			&u.TOCConfig,
			&lastWarnUpdateUnix,
			&u.LastWarnLevel,
			&u.OfflineMsgCount,
		)
		if err != nil {
			return nil, err
		}
		u.IdentScreenName = NewIdentScreenName(sn)
		u.LastWarnUpdate = time.Unix(lastWarnUpdateUnix, 0).UTC()
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (f SQLiteUserStore) InsertUser(ctx context.Context, u User) error {
	if u.DisplayScreenName.IsUIN() && !u.IsICQ {
		return errors.New("inserting user with UIN and isICQ=false")
	}
	q := `
		INSERT INTO users (identScreenName, displayScreenName, authKey, weakMD5Pass, strongMD5Pass, isICQ, isBot)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (identScreenName) DO NOTHING
	`
	result, err := f.db.ExecContext(ctx,
		q,
		u.IdentScreenName.String(),
		u.DisplayScreenName,
		u.AuthKey,
		u.WeakMD5Pass,
		u.StrongMD5Pass,
		u.IsICQ,
		u.IsBot,
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrDupUser
	}

	return nil
}

func (f SQLiteUserStore) DeleteUser(ctx context.Context, screenName IdentScreenName) error {
	q := `
		DELETE FROM users WHERE identScreenName = ?
	`
	result, err := f.db.ExecContext(ctx, q, screenName.String())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrNoUser
	}

	return nil
}

func (f SQLiteUserStore) SetUserPassword(ctx context.Context, screenName IdentScreenName, newPassword string) error {
	tx, err := f.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()

	q := `
		SELECT
			authKey,
			isICQ
		FROM users
		WHERE identScreenName = ?
	`

	u := User{}

	err = tx.QueryRowContext(ctx, q, screenName.String()).Scan(
		&u.AuthKey,
		&u.IsICQ,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return ErrNoUser
	}

	if err = u.HashPassword(newPassword); err != nil {
		return err
	}

	q = `
		UPDATE users
		SET authKey = ?, weakMD5Pass = ?, strongMD5Pass = ?
		WHERE identScreenName = ?
	`
	result, err := tx.ExecContext(ctx, q, u.AuthKey, u.WeakMD5Pass, u.StrongMD5Pass, screenName.String())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		// it's possible the user didn't change OR the user doesn't exist.
		// check if the user exists.
		var exists int
		err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE identScreenName = ?", u.IdentScreenName.String()).Scan(&exists)
		if err != nil {
			return err // Handle possible SQL errors during the select
		}
		if exists == 0 {
			err = ErrNoUser // User does not exist
			return err
		}
	}

	return tx.Commit()
}

func (f SQLiteUserStore) Feedbag(ctx context.Context, screenName IdentScreenName) ([]wire.FeedbagItem, error) {
	q := `
		SELECT 
			groupID,
			itemID,
			classID,
			name,
			attributes
		FROM feedbag
		WHERE screenName = ?
	`

	rows, err := f.db.QueryContext(ctx, q, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []wire.FeedbagItem
	for rows.Next() {
		var item wire.FeedbagItem
		var attrs []byte
		if err := rows.Scan(&item.GroupID, &item.ItemID, &item.ClassID, &item.Name, &attrs); err != nil {
			return nil, err
		}
		if err := wire.UnmarshalBE(&item.TLVLBlock, bytes.NewBuffer(attrs)); err != nil {
			return items, err
		}
		items = append(items, item)
	}

	return items, nil
}

func (f SQLiteUserStore) FeedbagLastModified(ctx context.Context, screenName IdentScreenName) (time.Time, error) {
	var lastModified sql.NullInt64
	q := `SELECT MAX(lastModified) FROM feedbag WHERE screenName = ?`
	err := f.db.QueryRowContext(ctx, q, screenName.String()).Scan(&lastModified)
	return time.Unix(lastModified.Int64, 0), err
}

func (f SQLiteUserStore) FeedbagDelete(ctx context.Context, screenName IdentScreenName, items []wire.FeedbagItem) error {
	// todo add transaction
	q := `DELETE FROM feedbag WHERE screenName = ? AND itemID = ?`

	for _, item := range items {
		if _, err := f.db.ExecContext(ctx, q, screenName.String(), item.ItemID); err != nil {
			return err
		}
	}

	return nil
}

func (f SQLiteUserStore) FeedbagUpsert(ctx context.Context, screenName IdentScreenName, items []wire.FeedbagItem) error {
	q := `
		INSERT INTO feedbag (screenName, groupID, itemID, classID, name, attributes, pdMode, lastModified)
		VALUES (?, ?, ?, ?, ?, ?, ?, UNIXEPOCH())
		ON CONFLICT (screenName, groupID, itemID)
			DO UPDATE SET classID      = excluded.classID,
						  name         = excluded.name,
						  attributes   = excluded.attributes,
						  pdMode       = excluded.pdMode, 
						  lastModified = UNIXEPOCH()
	`

	for _, item := range items {
		buf := &bytes.Buffer{}
		if err := wire.MarshalBE(item.TLVLBlock, buf); err != nil {
			return err
		}

		if item.ClassID == wire.FeedbagClassIdBuddy ||
			item.ClassID == wire.FeedbagClassIDPermit ||
			item.ClassID == wire.FeedbagClassIDDeny {
			// insert screen name identifier
			item.Name = NewIdentScreenName(item.Name).String()
		}
		pdMode := uint8(0)
		if item.ClassID == wire.FeedbagClassIdPdinfo {
			var hasMode bool
			pdMode, hasMode = item.Uint8(wire.FeedbagAttributesPdMode)
			if !hasMode {
				// by default, QIP sends a PD info item entry with no mode
				pdMode = uint8(wire.FeedbagPDModePermitAll)
			}
		}
		_, err := f.db.ExecContext(ctx,
			q,
			screenName.String(),
			item.GroupID,
			item.ItemID,
			item.ClassID,
			item.Name,
			buf.Bytes(),
			pdMode)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f SQLiteUserStore) ClearBuddyListRegistry(ctx context.Context) error {
	if _, err := f.db.ExecContext(ctx, `DELETE FROM buddyListMode`); err != nil {
		return err
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM clientSideBuddyList`); err != nil {
		return err
	}
	return nil
}

func (f SQLiteUserStore) RegisterBuddyList(ctx context.Context, user IdentScreenName) error {
	q := `
		INSERT INTO buddyListMode (screenName, clientSidePDMode) VALUES(?, ?)
		ON CONFLICT (screenName) DO NOTHING
	`
	_, err := f.db.ExecContext(ctx, q, user.String(), wire.FeedbagPDModePermitAll)
	return err
}

func (f SQLiteUserStore) UnregisterBuddyList(ctx context.Context, user IdentScreenName) error {
	if _, err := f.db.ExecContext(ctx, `DELETE FROM buddyListMode WHERE screenName = ?`, user.String()); err != nil {
		return err
	}
	if _, err := f.db.ExecContext(ctx, `DELETE FROM clientSideBuddyList WHERE me = ?`, user.String()); err != nil {
		return err
	}
	return nil
}

func (f SQLiteUserStore) UseFeedbag(ctx context.Context, screenName IdentScreenName) error {
	q := `
		INSERT INTO buddyListMode (screenName, useFeedbag)
		VALUES (?, ?)
		ON CONFLICT (screenName)
			DO UPDATE SET clientSidePDMode = 0,
						  useFeedbag       = true
	`
	_, err := f.db.ExecContext(ctx, q, screenName.String(), true)
	return err
}

func (f SQLiteUserStore) SetPDMode(ctx context.Context, me IdentScreenName, pdMode wire.FeedbagPDMode) error {
	alreadySet, err := f.isPDModeEqual(ctx, me, pdMode)
	if err != nil {
		return fmt.Errorf("isPDModeEqual: %w", err)
	}
	if alreadySet {
		return nil
	}

	tx, err := f.db.Begin()
	if err != nil {
		return err
	}

	defer func() {
		_ = tx.Rollback()
	}()

	if err := setClientSidePDMode(ctx, tx, me, pdMode); err != nil {
		return fmt.Errorf("setClientSidePDMode: %w", err)
	}

	if err := clearClientSidePDFlags(ctx, tx, me, pdMode); err != nil {
		return fmt.Errorf("clearClientSidePDFlags: %w", err)
	}

	if err := clearBlankClientSideBuddies(ctx, tx, me, pdMode); err != nil {
		return fmt.Errorf("clearBlankClientSideBuddies: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

// isPDModeEqual indicates whether the current permit/deny mode is already set
// to pdMode.
func (f SQLiteUserStore) isPDModeEqual(ctx context.Context, me IdentScreenName, pdMode wire.FeedbagPDMode) (bool, error) {
	q := `
		SELECT true
		FROM buddyListMode
		WHERE screenName = ? AND clientSidePDMode = ?
	`
	var isEqual bool
	err := f.db.QueryRowContext(ctx, q, me.String(), pdMode).Scan(&isEqual)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return isEqual, nil
}

// setClientSidePDMode sets the permit/deny mode for my client-side buddy list.
func setClientSidePDMode(ctx context.Context, tx *sql.Tx, me IdentScreenName, pdMode wire.FeedbagPDMode) error {
	q := `
		INSERT INTO buddyListMode (screenName, clientSidePDMode) VALUES(?, ?)
		ON CONFLICT (screenName)
			DO UPDATE SET clientSidePDMode = excluded.clientSidePDMode
	`
	_, err := tx.ExecContext(ctx, q, me.String(), pdMode)
	if err != nil {
		return err
	}
	return nil
}

// clearBlankClientSideBuddies removes client-side buddy where all flags
// (isBuddy, isPermit, isDeny) are false.
func clearBlankClientSideBuddies(ctx context.Context, tx *sql.Tx, me IdentScreenName, pdMode wire.FeedbagPDMode) error {
	q := `
		DELETE FROM clientSideBuddyList
		WHERE isBuddy IS FALSE
		  AND isPermit IS FALSE
		  AND isDeny IS FALSE
		  AND me = ?
	`
	_, err := tx.ExecContext(ctx, q, me.String(), pdMode)
	return err
}

// clearClientSidePDFlags clears permit/deny flags.
func clearClientSidePDFlags(ctx context.Context, tx *sql.Tx, me IdentScreenName, pdMode wire.FeedbagPDMode) error {
	q := `
		UPDATE clientSideBuddyList
		SET isDeny = false, isPermit = false
		WHERE me = ?
	`
	_, err := tx.ExecContext(ctx, q, me.String(), pdMode)
	return err
}

func (f SQLiteUserStore) AddBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		INSERT INTO clientSideBuddyList (me, them, isBuddy)
		VALUES (?, ?, true)
		ON CONFLICT (me, them) DO UPDATE SET isBuddy = true
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) RemoveBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		UPDATE clientSideBuddyList
		SET isBuddy = false
		WHERE me = ?
		  AND them = ?
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) DenyBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		INSERT INTO clientSideBuddyList (me, them, isDeny)
		VALUES (?, ?, 1)
		ON CONFLICT (me, them) DO UPDATE SET isDeny = 1
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) RemoveDenyBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		UPDATE clientSideBuddyList
		SET isDeny = false
		WHERE me = ?
		  AND them = ?
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) PermitBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		INSERT INTO clientSideBuddyList (me, them, isPermit)
		VALUES (?, ?, 1)
		ON CONFLICT (me, them) DO UPDATE SET isPermit = 1
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) RemovePermitBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		UPDATE clientSideBuddyList
		SET isPermit = false
		WHERE me = ?
		  AND them = ?
	`
	_, err := f.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

func (f SQLiteUserStore) Profile(ctx context.Context, screenName IdentScreenName) (UserProfile, error) {
	q := `
		SELECT IFNULL(body, ''), IFNULL(mimeType, ''), IFNULL(updateTime, 0)
		FROM profile
		WHERE screenName = ?
	`
	var profile UserProfile
	var updateTimeUnix int64
	err := f.db.QueryRowContext(ctx, q, screenName.String()).Scan(&profile.ProfileText, &profile.MIMEType, &updateTimeUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return UserProfile{}, nil
	}
	if err != nil {
		return UserProfile{}, err
	}
	if updateTimeUnix > 0 {
		profile.UpdateTime = time.Unix(updateTimeUnix, 0).UTC()
	}
	return profile, nil
}

func (f SQLiteUserStore) SetProfile(ctx context.Context, screenName IdentScreenName, profile UserProfile) error {
	var updateTimeUnix int64
	if !profile.UpdateTime.IsZero() {
		updateTimeUnix = profile.UpdateTime.Unix()
	}
	q := `
		INSERT INTO profile (screenName, body, mimeType, updateTime)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (screenName)
			DO UPDATE SET body = excluded.body,
			              mimeType = excluded.mimeType,
			              updateTime = excluded.updateTime
	`
	_, err := f.db.ExecContext(ctx, q, screenName.String(), profile.ProfileText, profile.MIMEType, updateTimeUnix)
	return err
}

func (f SQLiteUserStore) SetDirectoryInfo(ctx context.Context, screenName IdentScreenName, info AIMNameAndAddr) error {
	q := `
		UPDATE users SET 
			aim_firstName = ?,
			aim_lastName = ?,
			aim_middleName = ?,
			aim_maidenName = ?,
			aim_country = ?,
			aim_state = ?,
			aim_city = ?,
			aim_nickName = ?,
			aim_zipCode = ?,
			aim_address = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		info.FirstName,
		info.LastName,
		info.MiddleName,
		info.MaidenName,
		info.Country,
		info.State,
		info.City,
		info.NickName,
		info.ZIPCode,
		info.Address,
		screenName.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}

	return nil
}

func (f SQLiteUserStore) InsertBARTItem(ctx context.Context, hash []byte, blob []byte, itemType uint16) error {
	q := `
		INSERT INTO bartItem (hash, body, type)
		VALUES (?, ?, ?)
	`
	_, err := f.db.ExecContext(ctx, q, hash, blob, itemType)
	if err != nil {
		if liteErr, ok := err.(*sqlite.Error); ok {
			code := liteErr.Code()
			if code == lib.SQLITE_CONSTRAINT_PRIMARYKEY {
				return ErrBARTItemExists
			}
		}
		return err
	}
	return nil
}

func (f SQLiteUserStore) BARTItem(ctx context.Context, hash []byte) ([]byte, error) {
	q := `
		SELECT body
		FROM bartItem
		WHERE hash = ?
	`
	var body []byte
	err := f.db.QueryRowContext(ctx, q, hash).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return body, err
}

// BARTItem represents a BART asset with its hash and type.
type BARTItem struct {
	Hash string
	Type uint16
}

func (f SQLiteUserStore) ListBARTItems(ctx context.Context, itemType uint16) ([]BARTItem, error) {
	q := `
		SELECT hash, type
		FROM bartItem
		WHERE type = ?
	`

	rows, err := f.db.QueryContext(ctx, q, itemType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []BARTItem
	for rows.Next() {
		var item BARTItem
		var hashBytes []byte
		err := rows.Scan(&hashBytes, &item.Type)
		if err != nil {
			return nil, err
		}
		item.Hash = hex.EncodeToString(hashBytes)
		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (f SQLiteUserStore) DeleteBARTItem(ctx context.Context, hash []byte) error {
	q := `
		DELETE FROM bartItem
		WHERE hash = ?
	`
	result, err := f.db.ExecContext(ctx, q, hash)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return ErrBARTItemNotFound
	}

	return nil
}

func (f SQLiteUserStore) ChatRoomByCookie(ctx context.Context, chatCookie string) (ChatRoom, error) {
	chatRoom := ChatRoom{}

	q := `
		SELECT exchange, name, created, creator
		FROM chatRoom
		WHERE lower(cookie) = lower(?)
	`
	var creator string
	err := f.db.QueryRowContext(ctx, q, chatCookie).Scan(
		&chatRoom.exchange,
		&chatRoom.name,
		&chatRoom.createTime,
		&creator,
	)
	if errors.Is(err, sql.ErrNoRows) {
		err = fmt.Errorf("%w: %s", ErrChatRoomNotFound, chatCookie)
	}
	chatRoom.creator = NewIdentScreenName(creator)

	return chatRoom, err
}

func (f SQLiteUserStore) ChatRoomByName(ctx context.Context, exchange uint16, name string) (ChatRoom, error) {
	chatRoom := ChatRoom{
		exchange: exchange,
	}

	q := `
		SELECT name, created, creator
		FROM chatRoom
		WHERE exchange = ? AND lower(name) = lower(?)
	`
	var creator string
	err := f.db.QueryRowContext(ctx, q, exchange, name).Scan(
		&chatRoom.name,
		&chatRoom.createTime,
		&creator,
	)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrChatRoomNotFound
	}
	chatRoom.creator = NewIdentScreenName(creator)

	return chatRoom, err
}

func (f SQLiteUserStore) CreateChatRoom(ctx context.Context, chatRoom *ChatRoom) error {
	chatRoom.createTime = time.Now().UTC()
	q := `
		INSERT INTO chatRoom (cookie, exchange, name, created, creator)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err := f.db.ExecContext(ctx,
		q,
		chatRoom.Cookie(),
		chatRoom.Exchange(),
		chatRoom.Name(),
		chatRoom.createTime,
		chatRoom.Creator().String(),
	)

	if err != nil {
		if strings.Contains(err.Error(), "constraint failed") {
			err = ErrDupChatRoom
		}
		err = fmt.Errorf("CreateChatRoom: %w", err)
	}
	return err
}

func (f SQLiteUserStore) AllChatRooms(ctx context.Context, exchange uint16) ([]ChatRoom, error) {
	q := `
		SELECT created, creator, name
		FROM chatRoom
		WHERE exchange = ?
		ORDER BY created ASC
	`
	rows, err := f.db.QueryContext(ctx, q, exchange)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []ChatRoom
	for rows.Next() {
		cr := ChatRoom{
			exchange: exchange,
		}
		var creator string
		if err := rows.Scan(&cr.createTime, &creator, &cr.name); err != nil {
			return nil, err
		}
		cr.creator = NewIdentScreenName(creator)
		users = append(users, cr)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return users, nil
}

func (f SQLiteUserStore) DeleteChatRooms(ctx context.Context, exchange uint16, names []string) error {
	if len(names) == 0 {
		return nil
	}

	// Build the query with placeholders for each name
	placeholders := make([]string, len(names))
	args := make([]interface{}, 0, len(names)+1)
	args = append(args, exchange)

	for i, name := range names {
		placeholders[i] = "?"
		args = append(args, name)
	}

	q := fmt.Sprintf(`
		DELETE FROM chatRoom
		WHERE exchange = ? AND name IN (%s)
	`, strings.Join(placeholders, ","))

	_, err := f.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("DeleteChatRooms: %w", err)
	}

	return nil
}

func (f SQLiteUserStore) UpdateDisplayScreenName(ctx context.Context, displayScreenName DisplayScreenName) error {
	q := `
		UPDATE users
		SET displayScreenName = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, displayScreenName.String(), displayScreenName.IdentScreenName().String())
	return err
}

func (f SQLiteUserStore) UpdateEmailAddress(ctx context.Context, screenName IdentScreenName, emailAddress *mail.Address) error {
	q := `
		UPDATE users
		SET emailAddress = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, emailAddress.Address, screenName.String())
	return err
}

func (f SQLiteUserStore) EmailAddress(ctx context.Context, screenName IdentScreenName) (*mail.Address, error) {
	q := `
		SELECT emailAddress
		FROM users
		WHERE identScreenName = ?
	`
	var emailAddress string
	err := f.db.QueryRowContext(ctx, q, screenName.String()).Scan(&emailAddress)
	// username isn't found for some reason
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	e, err := mail.ParseAddress(emailAddress)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoEmailAddress, err)
	}
	return e, nil
}

func (f SQLiteUserStore) UpdateRegStatus(ctx context.Context, screenName IdentScreenName, regStatus uint16) error {
	q := `
		UPDATE users
		SET regStatus = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, regStatus, screenName.String())
	return err
}

func (f SQLiteUserStore) RegStatus(ctx context.Context, screenName IdentScreenName) (uint16, error) {
	q := `
		SELECT regStatus
		FROM users
		WHERE identScreenName = ?
	`
	var regStatus uint16
	err := f.db.QueryRowContext(ctx, q, screenName.String()).Scan(&regStatus)
	// username isn't found for some reason
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return regStatus, nil
}

func (f SQLiteUserStore) UpdateConfirmStatus(ctx context.Context, screenName IdentScreenName, confirmStatus bool) error {
	q := `
		UPDATE users
		SET confirmStatus = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, confirmStatus, screenName.String())
	return err
}

func (f SQLiteUserStore) ConfirmStatus(ctx context.Context, screenName IdentScreenName) (bool, error) {
	q := `
		SELECT confirmStatus
		FROM users
		WHERE identScreenName = ?
	`
	var confirmStatus bool
	err := f.db.QueryRowContext(ctx, q, screenName.String()).Scan(&confirmStatus)
	// username isn't found for some reason
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	return confirmStatus, nil
}

func (f SQLiteUserStore) UpdateSuspendedStatus(ctx context.Context, suspendedStatus uint16, screenName IdentScreenName) error {
	q := `
		UPDATE users
		SET suspendedStatus = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, suspendedStatus, screenName.String())
	return err
}

func (f SQLiteUserStore) SetBotStatus(ctx context.Context, isBot bool, screenName IdentScreenName) error {
	q := `
		UPDATE users
		SET isBot = ?
		WHERE identScreenName = ?
	`
	_, err := f.db.ExecContext(ctx, q, isBot, screenName.String())
	return err
}

func (f SQLiteUserStore) SetWorkInfo(ctx context.Context, name IdentScreenName, data ICQWorkInfo) error {
	q := `
		UPDATE users SET 
			icq_workInfo_company = ?,
			icq_workInfo_department = ?,
			icq_workInfo_occupationCode = ?,
			icq_workInfo_position = ?,
			icq_workInfo_address = ?,
			icq_workInfo_city = ?,
			icq_workInfo_countryCode = ?,
			icq_workInfo_fax = ?,
			icq_workInfo_phone = ?,
			icq_workInfo_state = ?,
			icq_workInfo_webPage = ?,
			icq_workInfo_zipCode = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.Company,
		data.Department,
		data.OccupationCode,
		data.Position,
		data.Address,
		data.City,
		data.CountryCode,
		data.Fax,
		data.Phone,
		data.State,
		data.WebPage,
		data.ZIPCode,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SetMoreInfo(ctx context.Context, name IdentScreenName, data ICQMoreInfo) error {
	q := `
		UPDATE users SET 
			icq_moreInfo_birthDay = ?,
			icq_moreInfo_birthMonth = ?,
			icq_moreInfo_birthYear = ?,
			icq_moreInfo_gender = ?,
			icq_moreInfo_homePageAddr = ?,
			icq_moreInfo_lang1 = ?,
			icq_moreInfo_lang2 = ?,
			icq_moreInfo_lang3 = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.BirthDay,
		data.BirthMonth,
		data.BirthYear,
		data.Gender,
		data.HomePageAddr,
		data.Lang1,
		data.Lang2,
		data.Lang3,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SetUserNotes(ctx context.Context, name IdentScreenName, data ICQUserNotes) error {
	q := `
		UPDATE users
		SET icq_notes = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.Notes,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SetInterests(ctx context.Context, name IdentScreenName, data ICQInterests) error {
	q := `
		UPDATE users SET 
			icq_interests_code1 = ?,
			icq_interests_keyword1 = ?,
			icq_interests_code2 = ?,
			icq_interests_keyword2 = ?,
			icq_interests_code3 = ?,
			icq_interests_keyword3 = ?,
			icq_interests_code4 = ?,
			icq_interests_keyword4 = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.Code1,
		data.Keyword1,
		data.Code2,
		data.Keyword2,
		data.Code3,
		data.Keyword3,
		data.Code4,
		data.Keyword4,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SetAffiliations(ctx context.Context, name IdentScreenName, data ICQAffiliations) error {
	q := `
		UPDATE users SET 
			icq_affiliations_currentCode1 = ?,
			icq_affiliations_currentKeyword1 = ?,
			icq_affiliations_currentCode2 = ?,
			icq_affiliations_currentKeyword2 = ?,
			icq_affiliations_currentCode3 = ?,
			icq_affiliations_currentKeyword3 = ?,
			icq_affiliations_pastCode1 = ?,
			icq_affiliations_pastKeyword1 = ?,
			icq_affiliations_pastCode2 = ?,
			icq_affiliations_pastKeyword2 = ?,
			icq_affiliations_pastCode3 = ?,
			icq_affiliations_pastKeyword3 = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.CurrentCode1,
		data.CurrentKeyword1,
		data.CurrentCode2,
		data.CurrentKeyword2,
		data.CurrentCode3,
		data.CurrentKeyword3,
		data.PastCode1,
		data.PastKeyword1,
		data.PastCode2,
		data.PastKeyword2,
		data.PastCode3,
		data.PastKeyword3,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SetBasicInfo(ctx context.Context, name IdentScreenName, data ICQBasicInfo) error {
	q := `
		UPDATE users SET 
			icq_basicInfo_cellPhone = ?,
			icq_basicInfo_countryCode = ?,
			icq_basicInfo_emailAddress = ?,
			icq_basicInfo_firstName = ?,
			icq_basicInfo_gmtOffset = ?,
			icq_basicInfo_address = ?,
			icq_basicInfo_city = ?,
			icq_basicInfo_fax = ?,
			icq_basicInfo_phone = ?,
			icq_basicInfo_state = ?,
			icq_basicInfo_lastName = ?,
			icq_basicInfo_nickName = ?,
			icq_basicInfo_publishEmail = ?,
			icq_basicInfo_zipCode = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		data.CellPhone,
		data.CountryCode,
		data.EmailAddress,
		data.FirstName,
		data.GMTOffset,
		data.Address,
		data.City,
		data.Fax,
		data.Phone,
		data.State,
		data.LastName,
		data.Nickname,
		data.PublishEmail,
		data.ZIPCode,
		name.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

func (f SQLiteUserStore) SaveMessage(ctx context.Context, offlineMessage OfflineMessage) (newCount int, err error) {
	buf := &bytes.Buffer{}
	if err := wire.MarshalBE(offlineMessage.Message, buf); err != nil {
		return 0, fmt.Errorf("marshal: %w", err)
	}

	var tx *sql.Tx
	tx, err = f.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	const countQuery = `
		SELECT COUNT(1)
		FROM offlineMessage
		WHERE sender = ? AND recipient = ?
	`
	var currentCount int
	if err = tx.QueryRowContext(
		ctx,
		countQuery,
		offlineMessage.Sender.String(),
		offlineMessage.Recipient.String(),
	).Scan(&currentCount); err != nil {
		return 0, fmt.Errorf("count: %w", err)
	}

	if currentCount >= offlineInboxLimit {
		err = ErrOfflineInboxFull
		return 0, err
	}

	q := `
		INSERT INTO offlineMessage (sender, recipient, message, sent)
		VALUES (?, ?, ?, ?)
	`
	if _, err = tx.ExecContext(ctx,
		q,
		offlineMessage.Sender.String(),
		offlineMessage.Recipient.String(),
		buf.Bytes(),
		offlineMessage.Sent,
	); err != nil {
		if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_FOREIGNKEY {
			err = ErrNoUser
		} else {
			err = fmt.Errorf("insert: %w", err)
		}
		return 0, err
	}

	newCount = currentCount + 1
	updateQuery := `
		UPDATE users
		SET offlineMsgCount = ?
		WHERE identScreenName = ?
	`
	_, err = tx.ExecContext(ctx,
		updateQuery,
		newCount,
		offlineMessage.Recipient.String(),
	)
	if err != nil {
		return 0, fmt.Errorf("update offlineMsgCount: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}

	return newCount, nil
}

func (f SQLiteUserStore) RetrieveMessages(ctx context.Context, recip IdentScreenName) ([]OfflineMessage, error) {
	q := `
		SELECT 
		    sender, 
		    message,
		    sent
		FROM offlineMessage
		WHERE recipient = ?
	`
	rows, err := f.db.QueryContext(ctx, q, recip.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []OfflineMessage

	for rows.Next() {
		var sender string
		var buf []byte
		var sent time.Time
		if err := rows.Scan(&sender, &buf, &sent); err != nil {
			return nil, err
		}

		var msg wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		if err := wire.UnmarshalBE(&msg, bytes.NewBuffer(buf)); err != nil {
			return nil, fmt.Errorf("unmarshal: %w", err)
		}

		messages = append(messages, OfflineMessage{
			Sender:    NewIdentScreenName(sender),
			Recipient: recip,
			Message:   msg,
			Sent:      sent,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

func (f SQLiteUserStore) DeleteMessages(ctx context.Context, recip IdentScreenName) error {
	q := `
		DELETE FROM offlineMessage WHERE recipient = ?
	`
	_, err := f.db.ExecContext(ctx, q, recip.String())
	return err
}

func (f SQLiteUserStore) BuddyIconMetadata(ctx context.Context, screenName IdentScreenName) (*wire.BARTID, error) {
	q := `
		SELECT
			groupID,
			itemID,
			classID,
			name,
			attributes
		FROM feedBag
		WHERE screenname = ? AND name = ? AND classID = ?
	`
	var item wire.FeedbagItem
	var attrs []byte
	err := f.db.QueryRowContext(ctx, q, screenName.String(), wire.BARTTypesBuddyIcon, wire.FeedbagClassIdBart).Scan(&item.GroupID, &item.ItemID, &item.ClassID, &item.Name, &attrs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := wire.UnmarshalBE(&item.TLVLBlock, bytes.NewBuffer(attrs)); err != nil {
		return nil, err
	}
	b, hasBuf := item.Bytes(wire.FeedbagAttributesBartInfo)
	if !hasBuf {
		return nil, errors.New("unable to extract icon payload")
	}
	bartInfo := wire.BARTInfo{}
	if err := wire.UnmarshalBE(&bartInfo, bytes.NewBuffer(b)); err != nil {
		return nil, err
	}
	return &wire.BARTID{
		Type: wire.BARTTypesBuddyIcon,
		BARTInfo: wire.BARTInfo{
			Flags: bartInfo.Flags,
			Hash:  bartInfo.Hash,
		},
	}, nil

}

func (f SQLiteUserStore) SetKeywords(ctx context.Context, screenName IdentScreenName, keywords [5]string) error {
	q := `
		WITH interests AS (SELECT CASE WHEN name = ? THEN id ELSE NULL END AS aim_keyword1,
								  CASE WHEN name = ? THEN id ELSE NULL END AS aim_keyword2,
								  CASE WHEN name = ? THEN id ELSE NULL END AS aim_keyword3,
								  CASE WHEN name = ? THEN id ELSE NULL END AS aim_keyword4,
								  CASE WHEN name = ? THEN id ELSE NULL END AS aim_keyword5
						   FROM aimKeyword
						   WHERE name IN (?, ?, ?, ?, ?))
		UPDATE users
		SET aim_keyword1 = (SELECT aim_keyword1 FROM interests WHERE aim_keyword1 IS NOT NULL),
			aim_keyword2 = (SELECT aim_keyword2 FROM interests WHERE aim_keyword2 IS NOT NULL),
			aim_keyword3 = (SELECT aim_keyword3 FROM interests WHERE aim_keyword3 IS NOT NULL),
			aim_keyword4 = (SELECT aim_keyword4 FROM interests WHERE aim_keyword4 IS NOT NULL),
			aim_keyword5 = (SELECT aim_keyword5 FROM interests WHERE aim_keyword5 IS NOT NULL)
		WHERE identScreenName = ?
	`

	_, err := f.db.ExecContext(ctx, q,
		keywords[0], keywords[1], keywords[2], keywords[3], keywords[4],
		keywords[0], keywords[1], keywords[2], keywords[3], keywords[4],
		screenName.String())
	return err
}

func (f SQLiteUserStore) Categories(ctx context.Context) ([]Category, error) {
	q := `SELECT id, name FROM aimKeywordCategory ORDER BY name`

	rows, err := f.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var categories []Category
	for rows.Next() {
		category := Category{}
		if err := rows.Scan(&category.ID, &category.Name); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return categories, nil
}

func (f SQLiteUserStore) CreateCategory(ctx context.Context, name string) (Category, error) {
	tx, err := f.db.Begin()
	if err != nil {
		return Category{}, err
	}

	defer tx.Rollback()

	q := `INSERT INTO aimKeywordCategory (name) VALUES (?)`
	res, err := tx.ExecContext(ctx, q, name)
	if err != nil {
		if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_UNIQUE {
			err = ErrKeywordCategoryExists
		}
		return Category{}, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Category{}, err
	}

	if id > math.MaxUint8 {
		return Category{}, errTooManyCategories
	}

	if err := tx.Commit(); err != nil {
		return Category{}, err
	}

	return Category{
		ID:   uint8(id),
		Name: name,
	}, nil
}

func (f SQLiteUserStore) DeleteCategory(ctx context.Context, categoryID uint8) error {
	q := `DELETE FROM aimKeywordCategory WHERE id = ?`
	res, err := f.db.ExecContext(ctx, q, categoryID)
	if err != nil {
		// Check if the error is a foreign key constraint violation
		if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_FOREIGNKEY {
			return ErrKeywordInUse
		}
	}

	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrKeywordCategoryNotFound
	}

	return nil
}

func (f SQLiteUserStore) KeywordsByCategory(ctx context.Context, categoryID uint8) ([]Keyword, error) {
	q := `SELECT id, name FROM aimKeyword WHERE parent = ? ORDER BY name`
	if categoryID == 0 {
		q = `SELECT id, name FROM aimKeyword WHERE parent IS NULL ORDER BY name`
	}

	rows, err := f.db.QueryContext(ctx, q, categoryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keywords []Keyword
	for rows.Next() {
		keyword := Keyword{}
		if err := rows.Scan(&keyword.ID, &keyword.Name); err != nil {
			return nil, err
		}
		keywords = append(keywords, keyword)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(keywords) == 0 {
		var exists int
		err = f.db.QueryRow("SELECT COUNT(*) FROM aimKeywordCategory WHERE id = ?", categoryID).Scan(&exists)
		if err != nil {
			return nil, err
		}
		if exists == 0 {
			return nil, ErrKeywordCategoryNotFound
		}
	}

	return keywords, nil
}

func (f SQLiteUserStore) CreateKeyword(ctx context.Context, name string, categoryID uint8) (Keyword, error) {
	tx, err := f.db.Begin()
	if err != nil {
		return Keyword{}, err
	}

	defer tx.Rollback()

	q := `INSERT INTO aimKeyword (name, parent) VALUES (?, ?)`
	var parent interface{} = nil
	if categoryID != 0 {
		parent = categoryID
	}

	res, err := tx.ExecContext(ctx, q, name, parent)
	if err != nil {
		if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_UNIQUE {
			err = ErrKeywordExists
		} else if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_FOREIGNKEY {
			err = ErrKeywordCategoryNotFound
		}
		return Keyword{}, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Keyword{}, err
	}

	if id > math.MaxUint8 {
		return Keyword{}, errTooManyKeywords
	}

	if err := tx.Commit(); err != nil {
		return Keyword{}, err
	}

	return Keyword{
		ID:   uint8(id),
		Name: name,
	}, nil
}

func (f SQLiteUserStore) DeleteKeyword(ctx context.Context, id uint8) error {
	q := `DELETE FROM aimKeyword WHERE id = ?`
	res, err := f.db.ExecContext(ctx, q, id)

	if err != nil {
		// Check if the error is a foreign key constraint violation
		if sqliteErr, ok := err.(*sqlite.Error); ok && sqliteErr.Code() == lib.SQLITE_CONSTRAINT_FOREIGNKEY {
			return ErrKeywordInUse
		}
	}

	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrKeywordNotFound
	}

	return nil
}

// InterestList returns a list of keywords grouped by category used to render
// the AIM directory interests list. The list is made up of 3 types of elements:
//
// Categories
//
//	ID: The category ID
//	Cookie: The category name
//	Type: [wire.ODirKeywordCategory]
//
// Keywords
//
//	ID: The parent category ID
//	Cookie: The keyword name
//	Type: [wire.ODirKeyword]
//
// Top-level Keywords
//
//	ID: 0 (does not have a parent category)
//	Cookie: The keyword name
//	Type: [wire.ODirKeyword]
//
// Keywords are grouped contiguously by category and preceded by the category
// name. Top-level keywords appear by themselves. Categories and top-level
// keywords are sorted alphabetically. Keyword groups are sorted alphabetically.
//
// Conceptually, the list looks like this:
//
//	> Animals (top-level keyword, id=0)
//	> Artificial Intelligence (keyword, id=3)
//		> Cybersecurity (keyword, id=3)
//	> Music (category, id=1)
//		> Jazz (keyword, id=1)
//		> Rock (keyword, id=1)
//	> Sports (category, id=2)
//		> Basketball (keyword, id=2)
//		> Soccer (keyword, id=2)
//		> Tennis (keyword, id=2)
//	> Technology (category, id=3)
//	> Zoology (top-level keyword, id=0)
func (f SQLiteUserStore) InterestList(ctx context.Context) ([]wire.ODirKeywordListItem, error) {
	q := `
		WITH categories AS (
			SELECT
				name AS grouping,
				id,
				0 AS sortPrio,
				name
			FROM aimKeywordCategory
			UNION
			SELECT
				IFNULL(akc.name, ak.name) AS grouping,
				IFNULL(ak.parent, 0) AS id,
				CASE WHEN ak.parent IS NULL THEN 1 ELSE 2 END AS sortPrio,
				ak.name
			FROM aimKeyword ak
			LEFT JOIN aimKeywordCategory akc ON akc.id = ak.parent
			ORDER BY 1, 3, 4
		)
		SELECT
			id,
			sortPrio,
			name
		FROM categories
	`

	rows, err := f.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []wire.ODirKeywordListItem
	for rows.Next() {
		msg := wire.ODirKeywordListItem{}

		var sortPrio int
		if err := rows.Scan(&msg.ID, &sortPrio, &msg.Name); err != nil {
			return nil, err
		}
		switch sortPrio {
		case 0:
			msg.Type = wire.ODirKeywordCategory
		case 1, 2:
			msg.Type = wire.ODirKeyword
		}

		list = append(list, msg)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return list, nil
}

func (f SQLiteUserStore) SetTOCConfig(ctx context.Context, user IdentScreenName, config string) error {
	q := `
		UPDATE users
		SET tocConfig = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		config,
		user.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

// SetWarnLevel updates the last warn update time and warning level for a user.
func (f SQLiteUserStore) SetWarnLevel(ctx context.Context, user IdentScreenName, lastWarnUpdate time.Time, lastWarnLevel uint16) error {
	q := `
		UPDATE users
		SET lastWarnUpdate = ?, lastWarnLevel = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		lastWarnUpdate.Unix(),
		lastWarnLevel,
		user.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}

// SetOfflineMsgCount updates the offline message count for a user.
func (f SQLiteUserStore) SetOfflineMsgCount(ctx context.Context, screenName IdentScreenName, count int) error {
	q := `
		UPDATE users
		SET offlineMsgCount = ?
		WHERE identScreenName = ?
	`
	res, err := f.db.ExecContext(ctx,
		q,
		count,
		screenName.String(),
	)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	c, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if c == 0 {
		return ErrNoUser
	}
	return nil
}
