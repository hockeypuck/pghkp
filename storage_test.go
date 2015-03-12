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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	stdtesting "testing"

	"github.com/hockeypuck/pgtest"
	"github.com/hockeypuck/testing"
	"github.com/julienschmidt/httprouter"
	gc "gopkg.in/check.v1"

	"gopkg.in/hockeypuck/hkp.v0"
	"gopkg.in/hockeypuck/openpgp.v0"
)

func Test(t *stdtesting.T) { gc.TestingT(t) }

type S struct {
	pgtest.PGSuite
	storage *storage
	db      *sql.DB
	srv     *httptest.Server
}

var _ = gc.Suite(&S{})

func (s *S) SetUpTest(c *gc.C) {
	s.PGSuite.SetUpTest(c)

	c.Log(s.URL)
	var err error
	s.db, err = sql.Open("postgres", s.URL)
	c.Assert(err, gc.IsNil)

	s.db.Exec("DROP DATABASE hkp")

	st, err := New(s.db)
	c.Assert(err, gc.IsNil)
	s.storage = st.(*storage)

	r := httprouter.New()
	handler, err := hkp.NewHandler(s.storage)
	c.Assert(err, gc.IsNil)
	handler.Register(r)
	s.srv = httptest.NewServer(r)
}

func (s *S) TearDownTest(c *gc.C) {
	s.srv.Close()
	s.db.Exec("DROP DATABASE hkp")
	s.db.Close()
	s.PGSuite.TearDownTest(c)
}

func (s *S) addKey(c *gc.C, keyname string) {
	keytext, err := ioutil.ReadAll(testing.MustInput(keyname))
	c.Assert(err, gc.IsNil)
	res, err := http.PostForm(s.srv.URL+"/pks/add", url.Values{
		"keytext": []string{string(keytext)},
	})
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)
	defer res.Body.Close()
	_, err = ioutil.ReadAll(res.Body)
	c.Assert(err, gc.IsNil)
}

func (s *S) TestMD5(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	/*
		s.addKey(c, "sksdigest.asc")
		session, coll := s.storage.c()
		defer session.Close()
		var doc keyDoc
		err = coll.Find(bson.D{{"md5", "da84f40d830a7be2a3c0b7f2e146bfaa"}}).One(&doc)
		c.Assert(err, gc.IsNil)
	*/

	res, err = http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "ce353cf4")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Jenny Ondioline <jennyo@transient.net>")
}

func (s *S) TestAddDuplicates(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=hget&search=da84f40d830a7be2a3c0b7f2e146bfaa")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	for i := 0; i < 10; i++ {
		s.addKey(c, "sksdigest.asc")
	}

	/*
		session, coll := s.storage.c()
		defer session.Close()
		n, err := coll.Find(bson.D{{"md5", "da84f40d830a7be2a3c0b7f2e146bfaa"}}).Count()
		c.Assert(err, gc.IsNil)
		c.Assert(n, gc.Equals, 1)
	*/
}

func (s *S) TestResolve(c *gc.C) {
	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=0x44a2d1db")
	c.Assert(err, gc.IsNil)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)

	/*
		s.addKey(c, "uat.asc")
		var doc keyDoc
		session, coll := s.storage.c()
		defer session.Close()
		err = coll.Find(nil).One(&doc)
		c.Assert(err, gc.IsNil)
	*/

	// Should match
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0x44a2d1db", "0xf79362da44a2d1db", "0x81279eee7ec89fb781702adaf79362da44a2d1db",
		// as do subkeys
		"0xdb769d16cdb9ad53", "0xe9ebaf4195c1826c", "0x6cdc23d76cba8ca9",
		// contiguous words and email addresses match
		"casey", "marshall", "casey+marshall", "cAseY+MArSHaLL",
		"casey.marshall@gmail.com", "casey.marshall@gazzang.com"} {
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil)
		armor, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].ShortID(), gc.Equals, "44a2d1db")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserAttributes, gc.HasLen, 1)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@gazzang.com>")
	}

	// Shouldn't match any of these
	for _, search := range []string{
		"0xdeadbeef", "0xce353cf4", "0xd1db", "44a2d1db", "0xadaf79362da44a2d1db",
		"alice@example.com", "bob@example.com", "marshal", "com"} {
		res, err = http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil)
		res.Body.Close()
		c.Assert(res.StatusCode, gc.Equals, http.StatusNotFound)
	}
}

func (s *S) TestMerge(c *gc.C) {
	s.addKey(c, "alice_unsigned.asc")
	s.addKey(c, "alice_signed.asc")

	/*
		session, coll := s.storage.c()
		defer session.Close()
		n, err := coll.Find(nil).Count()
		c.Assert(err, gc.IsNil)
		c.Assert(n, gc.Equals, 1)
	*/

	res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=alice@example.com")
	c.Assert(err, gc.IsNil)
	armor, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	c.Assert(err, gc.IsNil)
	c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

	keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
	c.Assert(keys, gc.HasLen, 1)
	c.Assert(keys[0].ShortID(), gc.Equals, "23e0dcca")
	c.Assert(keys[0].UserIDs, gc.HasLen, 1)
	c.Assert(keys[0].UserIDs[0].Signatures, gc.HasLen, 2)
}

func (s *S) TestEd25519(c *gc.C) {
	s.addKey(c, "e68e311d.asc")

	// Should match, even if we don't fully support eddsa yet.
	for _, search := range []string{
		// short, long and full fingerprint key IDs match
		"0xe68e311d", "0x8d7c6b1a49166a46ff293af2d4236eabe68e311d",
		// contiguous words and email addresses match
		"casey", "marshall", "casey+marshall", "cAseY+MArSHaLL",
		"cmars@cmarstech.com", "casey.marshall@canonical.com"} {
		res, err := http.Get(s.srv.URL + "/pks/lookup?op=get&search=" + search)
		c.Assert(err, gc.IsNil)
		armor, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, gc.IsNil)
		c.Assert(res.StatusCode, gc.Equals, http.StatusOK)

		keys := openpgp.MustReadArmorKeys(bytes.NewBuffer(armor)).MustParse()
		c.Assert(keys, gc.HasLen, 1)
		c.Assert(keys[0].ShortID(), gc.Equals, "e68e311d")
		c.Assert(keys[0].UserIDs, gc.HasLen, 2)
		c.Assert(keys[0].UserIDs[0].Keywords, gc.Equals, "Casey Marshall <casey.marshall@canonical.com>")
		// crypto/openpgp doesn't yet understand ed25519 keys.
		c.Assert(keys[0].Parsed, gc.Equals, false)
	}
}
