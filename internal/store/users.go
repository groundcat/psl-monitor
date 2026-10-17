package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID             int64
	Username       string
	Email          string
	ReceiveReports bool
	Active         bool
	CreatedAt      time.Time
	LastLogin      time.Time
}

var ErrBadLogin = errors.New("invalid username or password")

func ValidatePassword(p string) error {
	if len(p) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if len(p) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

func ValidateUsername(u string) error {
	if len(u) < 2 || len(u) > 64 {
		return errors.New("username must be 2-64 characters")
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@", c)) {
			return errors.New("username may contain letters, digits and . _ - @")
		}
	}
	return nil
}

func (s *Store) CountUsers() int {
	var n int
	s.R.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n
}

func (s *Store) CreateUser(username, password, email string) (int64, error) {
	if err := ValidateUsername(username); err != nil {
		return 0, err
	}
	if err := ValidatePassword(password); err != nil {
		return 0, err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return 0, err
	}
	res, err := s.W.Exec(`INSERT INTO users(username,password_hash,email,created_at) VALUES(?,?,?,?)`, username, string(h), strings.TrimSpace(email), time.Now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, errors.New("username already exists")
		}
		return 0, err
	}
	return res.LastInsertId()
}

// dummyHash equalises timing for unknown users.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), 12)

func (s *Store) Authenticate(username, password string) (*User, error) {
	var id int64
	var hash string
	var active int
	err := s.R.QueryRow(`SELECT id,password_hash,active FROM users WHERE username=?`, username).Scan(&id, &hash, &active)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, ErrBadLogin
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || active != 1 {
		return nil, ErrBadLogin
	}
	s.W.Exec(`UPDATE users SET last_login=? WHERE id=?`, time.Now().Unix(), id)
	return s.GetUser(id)
}

func (s *Store) GetUser(id int64) (*User, error) {
	u := &User{}
	var rr, act int
	var ca, ll int64
	err := s.R.QueryRow(`SELECT id,username,email,receive_reports,active,created_at,last_login FROM users WHERE id=?`, id).Scan(&u.ID, &u.Username, &u.Email, &rr, &act, &ca, &ll)
	if err != nil {
		return nil, err
	}
	u.ReceiveReports, u.Active, u.CreatedAt, u.LastLogin = rr == 1, act == 1, FromUnix(ca), FromUnix(ll)
	return u, nil
}

func (s *Store) ListUsers() []User {
	rows, err := s.R.Query(`SELECT id,username,email,receive_reports,active,created_at,last_login FROM users ORDER BY username`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var rr, act int
		var ca, ll int64
		if rows.Scan(&u.ID, &u.Username, &u.Email, &rr, &act, &ca, &ll) == nil {
			u.ReceiveReports, u.Active, u.CreatedAt, u.LastLogin = rr == 1, act == 1, FromUnix(ca), FromUnix(ll)
			out = append(out, u)
		}
	}
	return out
}

func (s *Store) UpdateProfile(id int64, email string, reports bool) error {
	_, err := s.W.Exec(`UPDATE users SET email=?, receive_reports=? WHERE id=?`, strings.TrimSpace(email), b2i(reports), id)
	return err
}

func (s *Store) SetPassword(id int64, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}
	if _, err := s.W.Exec(`UPDATE users SET password_hash=? WHERE id=?`, string(h), id); err != nil {
		return err
	}
	// invalidate other sessions
	_, err = s.W.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	return err
}

func (s *Store) CheckPassword(id int64, password string) bool {
	var hash string
	if s.R.QueryRow(`SELECT password_hash FROM users WHERE id=?`, id).Scan(&hash) != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (s *Store) activeUserCount() int {
	var n int
	s.R.QueryRow(`SELECT COUNT(*) FROM users WHERE active=1`).Scan(&n)
	return n
}

func (s *Store) SetUserActive(id int64, active bool) error {
	if !active {
		u, err := s.GetUser(id)
		if err != nil {
			return err
		}
		if u.Active && s.activeUserCount() <= 1 {
			return errors.New("cannot disable the last active admin")
		}
		s.W.Exec(`DELETE FROM sessions WHERE user_id=?`, id)
	}
	_, err := s.W.Exec(`UPDATE users SET active=? WHERE id=?`, b2i(active), id)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	u, err := s.GetUser(id)
	if err != nil {
		return err
	}
	if u.Active && s.activeUserCount() <= 1 {
		return errors.New("cannot delete the last active admin")
	}
	_, err = s.W.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// ReportRecipients returns emails of active users opted in to reports.
func (s *Store) ReportRecipients() []string {
	rows, err := s.R.Query(`SELECT email FROM users WHERE active=1 AND receive_reports=1 AND email<>''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		rows.Scan(&e)
		out = append(out, e)
	}
	return out
}

// ---- sessions

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// CreateSession returns (token, csrf).
func (s *Store) CreateSession(userID int64, ttl time.Duration) (string, string, error) {
	tok, csrf := randomToken(32), randomToken(16)
	now := time.Now()
	_, err := s.W.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,created_at,expires_at) VALUES(?,?,?,?,?)`, hashToken(tok), userID, csrf, now.Unix(), now.Add(ttl).Unix())
	return tok, csrf, err
}

// Session resolves a session token to its user and CSRF token.
func (s *Store) Session(token string) (*User, string, error) {
	var uid, exp int64
	var csrf string
	err := s.R.QueryRow(`SELECT user_id, csrf, expires_at FROM sessions WHERE token_hash=?`, hashToken(token)).Scan(&uid, &csrf, &exp)
	if err != nil || exp < time.Now().Unix() {
		return nil, "", errors.New("no session")
	}
	u, err := s.GetUser(uid)
	if err != nil || !u.Active {
		return nil, "", errors.New("no session")
	}
	return u, csrf, nil
}

func (s *Store) DeleteSession(token string) {
	s.W.Exec(`DELETE FROM sessions WHERE token_hash=?`, hashToken(token))
}
