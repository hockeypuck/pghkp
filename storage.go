/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2014  Casey Marshall

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pghkp

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "github.com/lib/pq"
	"gopkg.in/errgo.v1"

	"gopkg.in/hockeypuck/hkp.v1/jsonhkp"
	hkpstorage "gopkg.in/hockeypuck/hkp.v1/storage"
	log "gopkg.in/hockeypuck/logrus.v0"
	"gopkg.in/hockeypuck/openpgp.v1"
)

const (
	maxFingerprintLen = 40
)

type storage struct {
	*sql.DB
	dbName string

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error
}

var _ hkpstorage.Storage = (*storage)(nil)

var crTablesSQL = []string{
	`CREATE TABLE IF NOT EXISTS keys (
rfingerprint TEXT NOT NULL,
doc jsonb NOT NULL,
ctime TIMESTAMP WITH TIME ZONE NOT NULL,
mtime TIMESTAMP WITH TIME ZONE NOT NULL,
md5 TEXT NOT NULL,
keywords tsvector
)`,
	`CREATE TABLE IF NOT EXISTS subkeys (
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL
)`,
}

var crIndexesSQL = []string{
	`ALTER TABLE keys ADD CONSTRAINT keys_pk PRIMARY KEY (rfingerprint);`,
	`ALTER TABLE keys ADD CONSTRAINT keys_md5 UNIQUE (md5);`,
	`CREATE INDEX keys_rfp ON keys(rfingerprint text_pattern_ops);`,
	`CREATE INDEX keys_ctime ON keys (ctime);`,
	`CREATE INDEX keys_mtime ON keys (mtime);`,
	`CREATE INDEX keys_keywords ON keys USING gin(keywords);`,

	`ALTER TABLE subkeys ADD CONSTRAINT subkeys_pk PRIMARY KEY (rsubfp);`,
	`ALTER TABLE subkeys ADD CONSTRAINT subkeys_fk FOREIGN KEY (rfingerprint) REFERENCES keys(rfingerprint);`,
	`CREATE INDEX subkeys_rfp ON subkeys(rsubfp text_pattern_ops);`,
}

var drConstraintsSQL = []string{
	`ALTER TABLE keys DROP CONSTRAINT keys_pk;`,
	`ALTER TABLE keys DROP CONSTRAINT keys_md5;`,
	`DROP INDEX keys_rfp;`,
	`DROP INDEX keys_ctime;`,
	`DROP INDEX keys_mtime;`,
	`DROP INDEX keys_keywords;`,

	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_pk;`,
	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_fk;`,
	`DROP INDEX subkeys_rfp;`,
}

// Dial returns PostgreSQL storage connected to the given database URL.
func Dial(url string) (hkpstorage.Storage, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return New(db)
}

// New returns a PostgreSQL storage implementation for an HKP service.
func New(db *sql.DB) (hkpstorage.Storage, error) {
	st := &storage{
		DB: db,
	}
	err := st.createTables()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	st.createIndexes()
	return st, nil
}

func (st *storage) createTables() error {
	for _, crTableSQL := range crTablesSQL {
		_, err := st.Exec(crTableSQL)
		if err != nil {
			return errgo.Mask(err)
		}
	}
	return nil
}

func (st *storage) createIndexes() {
	for _, crIndexSQL := range crIndexesSQL {
		_, err := st.Exec(crIndexSQL)
		if err != nil {
			log.Warningf("error executing %q: %v", crIndexSQL, err)
		}
	}
}

type keyDoc struct {
	RFingerprint string
	CTime        time.Time
	MTime        time.Time
	MD5          string
	Doc          string
	Keywords     []string
}

func (st *storage) MatchMD5(md5s []string) ([]string, error) {
	var md5In []string
	for _, md5 := range md5s {
		// Must validate to prevent SQL injection since we're appending SQL strings here.
		_, err := hex.DecodeString(md5)
		if err != nil {
			return nil, errgo.Notef(err, "invalid MD5 %q", md5)
		}
		md5In = append(md5In, "'"+strings.ToLower(md5)+"'")
	}

	sqlStr := fmt.Sprintf("SELECT rfingerprint FROM keys WHERE md5 IN (%s)", strings.Join(md5In, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []string
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err := rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

// Resolve implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
func (st *storage) Resolve(keyids []string) (_ []string, retErr error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM keys WHERE rfingerprint LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	var subKeyIDs []string
	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		if len(keyid) < maxFingerprintLen {
			var rfp string
			row := stmt.QueryRow(keyid)
			err = row.Scan(&rfp)
			if err == sql.ErrNoRows {
				subKeyIDs = append(subKeyIDs, keyid)
			} else if err != nil {
				return nil, errgo.Mask(err)
			}
			result = append(result, rfp)
		} else {
			result = append(result, keyid)
		}
	}

	if len(subKeyIDs) > 0 {
		subKeyResult, err := st.resolveSubKeys(subKeyIDs)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, subKeyResult...)
	}

	return result, nil
}

func (st *storage) resolveSubKeys(keyids []string) ([]string, error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM subkeys WHERE rsubfp LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		if len(keyid) < maxFingerprintLen {
			var rfp string
			row := stmt.QueryRow(keyid)
			err = row.Scan(&rfp)
			if err != nil && err != sql.ErrNoRows {
				return nil, errgo.Mask(err)
			}
			result = append(result, rfp)
		} else {
			result = append(result, keyid)
		}
	}

	return result, nil
}

func (st *storage) MatchKeyword(search []string) ([]string, error) {
	var result []string
	stmt, err := st.Prepare("SELECT rfingerprint FROM keys WHERE keywords @@ to_tsquery($1) LIMIT $2")
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer stmt.Close()

	for _, term := range search {
		term = strings.Join(strings.Split(strings.ToLower(term), " "), " & ")
		err = func() error {
			rows, err := stmt.Query(term, 100)
			if err != nil {
				return errgo.Mask(err)
			}
			defer rows.Close()
			for rows.Next() {
				var rfp string
				err = rows.Scan(&rfp)
				if err != nil && err != sql.ErrNoRows {
					return errgo.Mask(err)
				}
				result = append(result, rfp)
			}
			err = rows.Err()
			if err != nil {
				return errgo.Mask(err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (st *storage) ModifiedSince(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE mtime > $1 ORDER BY mtime DESC LIMIT 100", t.UTC())
	if err != nil {
		return nil, errgo.Mask(err)
	}
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err = rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}
	return result, nil
}

func (st *storage) FetchKeys(rfps []string) ([]*openpgp.PrimaryKey, error) {
	if len(rfps) == 0 {
		return nil, nil
	}

	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errgo.Notef(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []*openpgp.PrimaryKey
	for rows.Next() {
		var bufStr string
		err = rows.Scan(&bufStr)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		result = append(result, key)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return result, nil
}

func (st *storage) FetchKeyrings(rfps []string) ([]*hkpstorage.Keyring, error) {
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errgo.Notef(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT ctime, mtime, doc FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errgo.Mask(err)
	}

	var result []*hkpstorage.Keyring
	for rows.Next() {
		var bufStr string
		var kr hkpstorage.Keyring
		err = rows.Scan(&bufStr, &kr.CTime, &kr.MTime)
		if err != nil && err != sql.ErrNoRows {
			return nil, errgo.Mask(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errgo.Mask(err)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := readOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errgo.Mask(err)
		}
		kr.PrimaryKey = key
		result = append(result, &kr)
	}
	err = rows.Err()
	if err != nil {
		return nil, errgo.Mask(err)
	}

	return result, nil
}

func readOneKey(b []byte, rfingerprint string) (*openpgp.PrimaryKey, error) {
	c := openpgp.ReadKeys(bytes.NewBuffer(b))
	defer func() {
		for _ = range c {
		}
	}()
	var result *openpgp.PrimaryKey
	for readKey := range c {
		if readKey.Error != nil {
			return nil, errgo.Mask(readKey.Error)
		}
		if result != nil {
			return nil, errgo.Newf("multiple keys in keyring: %v, %v", result.Fingerprint(), readKey.Fingerprint())
		}
		if readKey.PrimaryKey.RFingerprint != rfingerprint {
			return nil, errgo.Newf("RFingerprint mismatch: expected=%q got=%q",
				rfingerprint, readKey.PrimaryKey.RFingerprint)
		}
		result = readKey.PrimaryKey
	}
	return result, nil
}

func (st *storage) Insert(keys []*openpgp.PrimaryKey) (n int, retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	stmt, err := tx.Prepare("INSERT INTO keys (rfingerprint, ctime, mtime, md5, doc, keywords) " +
		"SELECT $1::TEXT, $2::TIMESTAMP, $3::TIMESTAMP, $4::TEXT, $5::JSONB, to_tsvector($6) " +
		"WHERE NOT EXISTS (SELECT 1 FROM keys WHERE rfingerprint = $1)")
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer stmt.Close()

	subStmt, err := tx.Prepare("INSERT INTO subkeys (rfingerprint, rsubfp) " +
		"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)")
	if err != nil {
		return 0, errgo.Mask(err)
	}
	defer subStmt.Close()

	var result hkpstorage.InsertError
	for _, key := range keys {
		openpgp.Sort(key)

		now := time.Now().UTC()
		jsonKey := jsonhkp.NewPrimaryKey(key)
		jsonBuf, err := json.Marshal(jsonKey)
		if err != nil {
			result.Errors = append(result.Errors, errgo.Notef(err, "cannot serialize rfp=%q", key.RFingerprint))
			continue
		}

		jsonStr := string(jsonBuf)
		keyword := strings.Join(keywords(key), " & ")
		_, err = stmt.Exec(&key.RFingerprint, &now, &now, &key.MD5, &jsonStr, &keyword)
		if err != nil {
			result.Errors = append(result.Errors, errgo.Notef(err, "cannot insert rfp=%q", key.RFingerprint))
			continue
		}
		for _, subKey := range key.SubKeys {
			_, err = subStmt.Exec(&key.RFingerprint, &subKey.RFingerprint)
			if err != nil {
				result.Errors = append(result.Errors, errgo.Notef(err, "cannot insert rsubfp=%q", subKey.RFingerprint))
			}
		}
		st.Notify(hkpstorage.KeyAdded{
			Digest: key.MD5,
		})
		n++
	}

	if len(result.Duplicates) > 0 || len(result.Errors) > 0 {
		return n, result
	}
	return n, nil
}

func (st *storage) Update(key *openpgp.PrimaryKey, lastMD5 string) (retErr error) {
	tx, err := st.Begin()
	if err != nil {
		return errgo.Mask(err)
	}
	defer func() {
		if retErr != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	openpgp.Sort(key)

	now := time.Now().UTC()
	jsonKey := jsonhkp.NewPrimaryKey(key)
	jsonBuf, err := json.Marshal(jsonKey)
	keyword := strings.Join(keywords(key), " & ")
	_, err = tx.Exec("UPDATE keys SET mtime = $1, md5 = $2, keywords = to_tsvector($3), doc = $4 "+
		"WHERE rfingerprint = $5",
		&now, &key.MD5, &keyword, jsonBuf, &key.RFingerprint)
	if err != nil {
		return errgo.Mask(err)
	}
	for _, subKey := range key.SubKeys {
		_, err := tx.Exec("INSERT INTO subkeys (rfingerprint, rsubfp) "+
			"SELECT $1::TEXT, $2::TEXT WHERE NOT EXISTS (SELECT 1 FROM subkeys WHERE rsubfp = $2)",
			&key.RFingerprint, &subKey.RFingerprint)
		if err != nil {
			return errgo.Mask(err)
		}
	}

	st.Notify(hkpstorage.KeyReplaced{
		OldDigest: lastMD5,
		NewDigest: key.MD5,
	})
	return nil
}

// keywords returns a slice of searchable tokens extracted
// from the given UserID packet keywords string.
func keywords(key *openpgp.PrimaryKey) []string {
	m := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			m[s[lbr+1:rbr]] = true
		}
		if lbr != -1 {
			fields := strings.FieldsFunc(s[:lbr], func(r rune) bool {
				if !utf8.ValidRune(r) {
					return true
				}
				if unicode.IsLetter(r) || unicode.IsNumber(r) {
					return false
				}
				return true
			})
			for _, field := range fields {
				m[field] = true
			}
		}
	}
	var result []string
	for k := range m {
		result = append(result, k)
	}
	return result
}

func subkeys(key *openpgp.PrimaryKey) []string {
	var result []string
	for _, subkey := range key.SubKeys {
		result = append(result, subkey.RFingerprint)
	}
	return result
}

func (st *storage) Subscribe(f func(hkpstorage.KeyChange) error) {
	st.mu.Lock()
	st.listeners = append(st.listeners, f)
	st.mu.Unlock()
}

func (st *storage) Notify(change hkpstorage.KeyChange) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	log.Debugf("%v", change)
	for _, f := range st.listeners {
		// TODO: log error notifying listener?
		f(change)
	}
	return nil
}

func (st *storage) RenotifyAll() error {
	var result struct {
		MD5 string `bson:"md5"`
	}

	sqlStr := fmt.Sprintf("SELECT md5 FROM keys")
	rows, err := st.Query(sqlStr)
	if err != nil {
		return errgo.Mask(err)
	}

	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&result)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil
			} else {
				return errgo.Mask(err)
			}
		}
		st.Notify(hkpstorage.KeyAdded{Digest: result.MD5})
	}
	err = rows.Err()
	return errgo.Mask(err)
}
