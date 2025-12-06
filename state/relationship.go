package state

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"
)

// relationshipSQLTpl defines the template for a SQL query used to query buddy
// list and privacy relationships between a user (`me`) and other users in the
// system.
//
// This query serves two purposes:
// 1. Retrieve all relationships for the user.
// 2. If filtering is enabled (`.DoFilter` is true), retrieve all relationships
// filtered on a specific list of users.
//
// The query creates a unified view of both server-side buddy lists and
// client-side buddy lists.
const relationshipSQLTpl = `
WITH myScreenName AS (SELECT ?),
     {{ if .DoFilter }}filter AS (SELECT * FROM (VALUES%s) as t),{{ end }}

     -- get all users who have ~you~ on their buddy list
     theirBuddyLists AS (SELECT COALESCE(clientSide._screenName, feedbag._screenName) AS _screenName,
                              COALESCE(clientSide.isBuddy OR feedbag.isBuddy, FALSE) AS isBuddy,
                              COALESCE(clientSide.isPermit OR feedbag.isPermit, FALSE) AS isPermit,
                              COALESCE(clientSide.isDeny OR feedbag.isDeny, FALSE) AS isDeny
                       FROM (SELECT feedbag.screenName                                   AS _screenName,
                                    MAX(CASE WHEN feedbag.classId = 0 THEN 1 ELSE 0 END) AS isBuddy,
                                    MAX(CASE WHEN feedbag.classId = 2 THEN 1 ELSE 0 END) AS isPermit,
                                    MAX(CASE WHEN feedbag.classId = 3 THEN 1 ELSE 0 END) AS isDeny
                             FROM feedbag
                             WHERE feedbag.name = (SELECT * FROM myScreenName)
                             {{ if .DoFilter }}AND feedbag.screenName IN (SELECT * FROM filter){{ end }}
                               AND feedbag.classId IN (0, 2, 3)
                               AND EXISTS(SELECT 1
                                          FROM buddyListMode
                                          WHERE buddyListMode.screenName = feedbag.screenName
                                            AND useFeedbag IS TRUE)
                             GROUP BY feedbag.screenName) feedbag
                       FULL OUTER JOIN (SELECT me       AS _screenName,
                                               isBuddy  AS isBuddy,
                                               isPermit AS isPermit,
                                               isDeny   AS isDeny
                                        FROM clientSideBuddyList
                                        WHERE them = (SELECT * FROM myScreenName)
                                        {{ if .DoFilter }}AND me IN (SELECT * FROM filter){{ end }}) clientSide
                       ON feedbag._screenName = clientSide._screenName),

     -- get all users on ~your~ buddy list
     yourBuddyList AS (SELECT COALESCE(clientSide._screenName, feedbag._screenName) AS _screenName,
                              COALESCE(clientSide.isBuddy OR feedbag.isBuddy, FALSE) AS isBuddy,
                              COALESCE(clientSide.isPermit OR feedbag.isPermit, FALSE) AS isPermit,
                              COALESCE(clientSide.isDeny OR feedbag.isDeny, FALSE) AS isDeny
                       FROM (SELECT feedbag.name                                         AS _screenName,
                                    MAX(CASE WHEN feedbag.classId = 0 THEN 1 ELSE 0 END) AS isBuddy,
                                    MAX(CASE WHEN feedbag.classId = 2 THEN 1 ELSE 0 END) AS isPermit,
                                    MAX(CASE WHEN feedbag.classId = 3 THEN 1 ELSE 0 END) AS isDeny
                             FROM feedbag
                             WHERE feedbag.screenName = (SELECT * FROM myScreenName)
                             {{ if .DoFilter }}AND feedbag.name IN (SELECT * FROM filter){{ end }}
                               AND feedbag.classId IN (0, 2, 3)
                               AND EXISTS(SELECT 1
                                          FROM buddyListMode
                                          WHERE buddyListMode.screenName = feedbag.screenName
                                            AND useFeedbag IS TRUE)
                             GROUP BY feedbag.name) feedbag
                       FULL OUTER JOIN (SELECT them     AS _screenName,
                                               isBuddy  AS isBuddy,
                                               isPermit AS isPermit,
                                               isDeny   AS isDeny
                                        FROM clientSideBuddyList
                                        WHERE me = (SELECT * FROM myScreenName)
                                        {{ if .DoFilter }}AND them IN (SELECT * FROM filter){{ end }}) clientSide
                       ON feedbag._screenName = clientSide._screenName),

     -- get privacy prefs of all users who have ~you~ on their buddy list
     theirPrivacyPrefs AS (SELECT buddyListMode.screenName,
                                  CASE
                                      WHEN buddyListMode.useFeedbag IS TRUE THEN IFNULL(feedbagPrefs.pdMode, 1)
                                      ELSE buddyListMode.clientSidePDMode END AS pdMode
                           FROM buddyListMode
                                    LEFT JOIN feedbag feedbagPrefs
                                              ON (feedbagPrefs.screenName == buddyListMode.screenName AND
                                                  feedbagPrefs.classID = 4)
                           WHERE EXISTS (SELECT 1
                                         FROM theirBuddyLists
                                         WHERE theirBuddyLists._screenName = buddyListMode.screenName)
                              OR EXISTS (SELECT 1
                                         FROM yourBuddyList
                                         WHERE yourBuddyList._screenName = buddyListMode.screenName)),

     -- get privacy prefs of all users on ~your~ buddy list
     yourPrivacyPrefs AS (SELECT buddyListMode.screenName,
                                 CASE
                                     WHEN buddyListMode.useFeedbag IS TRUE THEN IFNULL(feedbagPrefs.pdMode, 1)
                                     ELSE buddyListMode.clientSidePDMode END AS pdMode
                          FROM buddyListMode
                                   LEFT JOIN feedbag feedbagPrefs
                                             ON (feedbagPrefs.screenName == buddyListMode.screenName AND
                                                 feedbagPrefs.classID = 4)
                          WHERE buddyListMode.screenName = (SELECT * FROM myScreenName))

-- create relationships between you and all combined users
SELECT COALESCE(yourBuddyList._screenName, theirBuddyLists._screenName) AS screenName,
       CASE
           WHEN yourPrivacyPrefs.pdMode = 1 THEN false
           WHEN yourPrivacyPrefs.pdMode = 2 THEN true
           WHEN yourPrivacyPrefs.pdMode = 3 THEN IFNULL(yourBuddyList.isPermit, false) = false
           WHEN yourPrivacyPrefs.pdMode = 4 THEN IFNULL(yourBuddyList.isDeny, false)
           WHEN yourPrivacyPrefs.pdMode = 5 THEN IFNULL(yourBuddyList.isBuddy, false) = false
           ELSE false
           END                                                        AS youBlock,
       CASE
           WHEN theirPrivacyPrefs.pdMode = 1 THEN false
           WHEN theirPrivacyPrefs.pdMode = 2 THEN true
           WHEN theirPrivacyPrefs.pdMode = 3 THEN IFNULL(theirBuddyLists.isPermit, false) = false
           WHEN theirPrivacyPrefs.pdMode = 4 THEN IFNULL(theirBuddyLists.isDeny, false)
           WHEN theirPrivacyPrefs.pdMode = 5 THEN IFNULL(theirBuddyLists.isBuddy, false) = false
           ELSE false
           END                                                        AS blocksYou,
       IFNULL(theirBuddyLists.isBuddy, false)                         AS onTheirBuddyList,
       IFNULL(yourBuddyList.isBuddy, false)                           AS onYourBuddyList
FROM theirBuddyLists
         FULL OUTER JOIN yourBuddyList
              ON (yourBuddyList._screenName = theirBuddyLists._screenName)
         JOIN theirPrivacyPrefs
              ON (theirPrivacyPrefs.screenName = COALESCE(theirBuddyLists._screenName, yourBuddyList._screenName))
         JOIN yourPrivacyPrefs ON (1 = 1)
`

var (
	queryWithoutFiltering = tmplMustCompile(struct{ DoFilter bool }{DoFilter: false})
	queryWithFiltering    = tmplMustCompile(struct{ DoFilter bool }{DoFilter: true})
)

// Relationship represents the relationship between two users.
// Users A and B are related if:
//   - A has user B on their buddy list, or vice versa
//   - A has user B on their deny list, or vice versa
//   - A has user B on their permit list, or vice versa
type Relationship struct {
	// User is the screen name of the user with whom you have a relationship.
	User IdentScreenName
	// BlocksYou indicates whether user blocks you. This is true when user has
	// the following permit/deny modes set:
	// 	- DenyAll
	// 	- PermitSome (and you are not on permit list)
	// 	- DenySome (and you are on deny list)
	// 	- PermitOnList (and you are not on their buddy list)
	BlocksYou bool
	// YouBlock indicates whether you block user. This is true when user has
	// the following permit/deny modes set:
	// 	- DenyAll
	// 	- PermitSome (and they are not on your permit list)
	// 	- DenySome (and they are on your deny list)
	// 	- PermitOnList (and they are not on your buddy list)
	YouBlock bool
	// IsOnTheirList indicates whether you are on user's buddy list.
	IsOnTheirList bool
	// IsOnYourList indicates whether this user is on your buddy list.
	IsOnYourList bool
}

// Relationship retrieves the relationship between the specified user (`me`)
// and another user (`them`).
//
// This method always returns a usable [Relationship] value. If the user
// specified by `them` does not exist, the returned [Relationship] will have
// default boolean values.
func (f SQLiteUserStore) Relationship(ctx context.Context, me IdentScreenName, them IdentScreenName) (Relationship, error) {
	rels, err := f.AllRelationships(ctx, me, []IdentScreenName{them})
	if err != nil {
		return Relationship{}, fmt.Errorf("error getting relationships: %w", err)
	}

	if len(rels) == 0 {
		return Relationship{
			User: them,
		}, nil
	}

	return rels[0], nil
}

// AllRelationships retrieves the relationships between the specified user (`me`)
// and other users.
//
// A relationship is defined by the [Relationship] type, which describes the nature
// of the connection between users.
//
// This function only includes users who have activated their buddy list through
// a call to [SQLiteUserStore.RegisterBuddyList]. The results can be optionally
// filtered to include only specific users by providing their identifiers in
// the `filter` parameter.
func (f SQLiteUserStore) AllRelationships(ctx context.Context, me IdentScreenName, filter []IdentScreenName) ([]Relationship, error) {
	tpl := queryWithoutFiltering
	args := make([]any, 1, len(filter)+1)
	args[0] = me.String()

	if len(filter) > 0 {
		// add placeholders to template
		placeholders := strings.TrimRight(strings.Repeat("(?),", len(filter)), ",")
		tpl = fmt.Sprintf(queryWithFiltering, placeholders)
		// assemble arguments to match placeholders
		for _, sn := range filter {
			args = append(args, sn.String())
		}
	}

	rows, err := f.db.QueryContext(ctx, tpl, args...)
	if err != nil {
		return nil, fmt.Errorf("error querying relationships: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	var relationships []Relationship
	for rows.Next() {
		var screenName string
		rel := Relationship{}
		err = rows.Scan(
			&screenName,
			&rel.YouBlock,
			&rel.BlocksYou,
			&rel.IsOnTheirList,
			&rel.IsOnYourList,
		)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		rel.User = NewIdentScreenName(screenName)
		relationships = append(relationships, rel)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over relationship rows: %w", err)
	}

	return relationships, nil
}

func tmplMustCompile(data any) string {
	tmpl, err := template.New("").Parse(relationshipSQLTpl)
	if err != nil {
		panic(err)
	}
	buf := &bytes.Buffer{}
	err = tmpl.Execute(buf, data)
	if err != nil {
		panic(err)
	}
	return buf.String()
}
