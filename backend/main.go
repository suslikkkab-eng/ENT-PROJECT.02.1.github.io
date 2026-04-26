package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var db *sql.DB
var jwtSecret []byte

type CodeData struct {
	Code      string
	ExpiresAt time.Time
	Attempts  int
}

var (
	codes      = make(map[string]CodeData)
	rateLimits = make(map[string][]time.Time)
	mu         sync.Mutex
)

// ---------- UTILS ----------

func jsonResponse(w http.ResponseWriter, status int, data map[string]interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

var allowedOrigins = map[string]bool{
	"https://suslikkkab-eng.github.io": true,
	"http://localhost:5500":            true,
	"http://127.0.0.1:5500":           true,
}


func corsWithOrigin(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")

	log.Println("METHOD:", r.Method, "PATH:", r.URL.Path, "ORIGIN:", origin)

	if origin == "" {
		return false
	}

	if !allowedOrigins[origin] {
		jsonResponse(w, 403, map[string]interface{}{"error": "Origin not allowed"})
		return true
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Vary", "Origin")

	if r.Method == "OPTIONS" {
		w.WriteHeader(204)
		return true
	}
	return false
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}

func checkRateLimit(key string, max int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)

	mu.Lock()
	defer mu.Unlock()

	var fresh []time.Time
	for _, t := range rateLimits[key] {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}

	if len(fresh) >= max {
		return false
	}

	rateLimits[key] = append(fresh, now)
	return true
}

func generateCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

// ---------- EMAIL ----------

func sendEmail(to, code string) error {
	from := os.Getenv("SMTP_EMAIL")
	pass := os.Getenv("SMTP_PASSWORD")

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Код подтверждения")
	m.SetBody("text/plain", "Ваш код: "+code)

	d := gomail.NewDialer("smtp.gmail.com", 587, from, pass)
	return d.DialAndSend(m)
}

// ---------- JWT ----------

func generateJWT(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})
	return token.SignedString(jwtSecret)
}

func parseJWT(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid claims")
	}
	return claims["email"].(string), nil
}

// ---------- DB ----------

func initDB() {
	var err error
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}

	db.Ping()

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE,
		password_hash TEXT,
		verified BOOLEAN DEFAULT FALSE
	)`); err != nil {
		log.Println("DB error:", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS profiles (
		user_id INTEGER UNIQUE,
		name TEXT,
		avatar_url TEXT
	)`); err != nil {
		log.Println("DB error:", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS test_results (
		id SERIAL PRIMARY KEY,
		user_id INTEGER,
		subject TEXT,
		score INTEGER,
		total INTEGER,
		percent FLOAT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		log.Println("DB error:", err)
	}

	fmt.Println("PostgreSQL connected")

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS refresh_tokens (
		id SERIAL PRIMARY KEY,
		user_id INTEGER,
		token TEXT,
		expires_at TIMESTAMP
	)`); err != nil {
		log.Println("DB error:", err)
	}
}

func generateRefreshToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ---------- MIDDLEWARE ----------

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if corsWithOrigin(w, r) { return }

		auth := r.Header.Get("Authorization")
		if auth == "" {
			jsonResponse(w, 401, map[string]interface{}{"error": "No token"})
			return
		}

		tokenStr := strings.Replace(auth, "Bearer ", "", 1)

		email, err := parseJWT(tokenStr)
		if err != nil {
			jsonResponse(w, 401, map[string]interface{}{"error": "Invalid token"})
			return
		}

		ctx := context.WithValue(r.Context(), "userEmail", email)
		next(w, r.WithContext(ctx))
	}
}

// ---------- AUTH ----------

func sendCodeHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	ip := getIP(r)
	if !checkRateLimit("send:"+ip, 2, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many requests"})
		return
	}

	email := r.URL.Query().Get("email")
	code := generateCode()

	mu.Lock()
	codes[email] = CodeData{Code: code, ExpiresAt: time.Now().Add(10 * time.Minute)}
	mu.Unlock()

	if err := sendEmail(email, code); err != nil {
		log.Println("email error:", err)
		jsonResponse(w, 500, map[string]interface{}{"error": "email failed"})
		return
	}

	jsonResponse(w, 200, map[string]interface{}{"status": "sent"})
}

func verifyCodeHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	ip := getIP(r)
	if !checkRateLimit("verify:"+ip, 5, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many attempts"})
		return
	}

	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")

	mu.Lock()
	data := codes[email]
	mu.Unlock()

	if time.Now().After(data.ExpiresAt) {
		jsonResponse(w, 400, map[string]interface{}{"error": "expired"})
		return
	}

	if data.Code == code {
		delete(codes, email)
		if _, err := db.Exec("UPDATE users SET verified=true WHERE email=$1", email); err != nil {
			log.Println("DB error:", err)
		}
		jsonResponse(w, 200, map[string]interface{}{"status": "verified"})
		return
	}

	jsonResponse(w, 400, map[string]interface{}{"error": "invalid"})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	ip := getIP(r)
	if !checkRateLimit("register:"+ip, 3, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many registrations"})
		return
	}

	email := r.FormValue("email")
	pass := r.FormValue("password")

	hash, _ := bcrypt.GenerateFromPassword([]byte(pass), 10)

	_, err := db.Exec("INSERT INTO users (email,password_hash,verified) VALUES ($1,$2,false)", email, string(hash))
	if err != nil {
		jsonResponse(w, 400, map[string]interface{}{"error": "exists"})
		return
	}

	jsonResponse(w, 200, map[string]interface{}{"status": "ok"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	ip := getIP(r)
	if !checkRateLimit("login:"+ip, 5, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many login attempts"})
		return
	}

	email := r.FormValue("email")
	pass := r.FormValue("password")

	var hash string
	var verified bool

	err := db.QueryRow("SELECT password_hash,verified FROM users WHERE email=$1", email).Scan(&hash, &verified)
	if err != nil || !verified {
		jsonResponse(w, 400, map[string]interface{}{"error": "invalid"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) != nil {
		jsonResponse(w, 400, map[string]interface{}{"error": "invalid"})
		return
	}

	token, _ := generateJWT(email)

	var id int
	db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&id)

	refresh := generateRefreshToken()
	if _, err = db.Exec(
		"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)",
		id, refresh, time.Now().Add(72*24*time.Hour),
	); err != nil {
		log.Println("DB error:", err)
	}

	jsonResponse(w, 200, map[string]interface{}{"token": token, "refresh": refresh})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	email, _ := parseJWT(token)

	jsonResponse(w, 200, map[string]interface{}{"email": email})
}

// ---------- PROFILE ----------

func profileHandler(w http.ResponseWriter, r *http.Request) {

	ip := getIP(r)
	if !checkRateLimit("profile:"+ip, 10, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many requests"})
		return
	}

	token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	email, _ := parseJWT(token)

	var id int
	db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&id)

	if r.Method == "POST" {
		name := r.FormValue("name")
		avatar := r.FormValue("avatar")

		if _, err := db.Exec(`INSERT INTO profiles (user_id,name,avatar_url)
		VALUES($1,$2,$3)
		ON CONFLICT (user_id) DO UPDATE SET name=$2,avatar_url=$3`,
			id, name, avatar); err != nil {
			log.Println("DB error:", err)
		}

		jsonResponse(w, 200, map[string]interface{}{"status": "updated"})
		return
	}

	var name, avatar string
	db.QueryRow("SELECT name,avatar_url FROM profiles WHERE user_id=$1", id).Scan(&name, &avatar)

	jsonResponse(w, 200, map[string]interface{}{"name": name, "avatar": avatar})
}

// ---------- TEST RESULTS ----------

func addResultHandler(w http.ResponseWriter, r *http.Request) {

	ip := getIP(r)
	if !checkRateLimit("tests:"+ip, 10, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many test submissions"})
		return
	}

	token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	email, _ := parseJWT(token)

	var id int
	db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&id)

	subject := r.FormValue("subject")
	score := r.FormValue("score")
	total := r.FormValue("total")

	var scoreInt, totalInt int
	fmt.Sscanf(score, "%d", &scoreInt)
	fmt.Sscanf(total, "%d", &totalInt)

	percent := 0.0
	if totalInt > 0 {
		percent = float64(scoreInt) / float64(totalInt) * 100
	}

	if _, err := db.Exec("INSERT INTO test_results (user_id,subject,score,total,percent) VALUES ($1,$2,$3,$4,$5)",
		id, subject, scoreInt, totalInt, percent); err != nil {
		log.Println("DB error:", err)
	}

	jsonResponse(w, 200, map[string]interface{}{"status": "saved"})
}

func getResultsHandler(w http.ResponseWriter, r *http.Request) {

	token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	email, _ := parseJWT(token)

	var id int
	db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&id)

	rows, err := db.Query("SELECT subject,score,total FROM test_results WHERE user_id=$1", id)
	if err != nil {
		jsonResponse(w, 500, map[string]interface{}{"error": "DB error"})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}

	for rows.Next() {
		var s string
		var sc, t int
		rows.Scan(&s, &sc, &t)

		results = append(results, map[string]interface{}{
			"subject": s,
			"score":   sc,
			"total":   t,
		})
	}

	jsonResponse(w, 200, map[string]interface{}{"results": results})
}

// ---------- STATS ----------

func statsHandler(w http.ResponseWriter, r *http.Request) {

	token := strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1)
	email, _ := parseJWT(token)

	var id int
	db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&id)

	var count int
	var avg float64

	db.QueryRow("SELECT COUNT(*),COALESCE(AVG(score),0) FROM test_results WHERE user_id=$1", id).Scan(&count, &avg)

	jsonResponse(w, 200, map[string]interface{}{
		"total_tests": count,
		"avg_score":   avg,
	})
}

// ---------- LEADERBOARD ----------

func leaderboardHandler(w http.ResponseWriter, r *http.Request) {

	rows, err := db.Query(`
SELECT u.email,
       COALESCE(p.name, '') as name,
       COALESCE(p.avatar_url, '') as avatar,
       COALESCE(AVG(t.percent), 0) as avg_score,
       COUNT(t.id) as total_tests
FROM users u
LEFT JOIN test_results t ON u.id = t.user_id
LEFT JOIN profiles p ON u.id = p.user_id
WHERE u.verified = true
GROUP BY u.id, p.name, p.avatar_url
ORDER BY avg_score DESC, total_tests DESC
LIMIT 20
`)
	if err != nil {
		jsonResponse(w, 500, map[string]interface{}{"error": "DB error"})
		return
	}
	defer rows.Close()

	var list []map[string]interface{}

	rank := 1

	for rows.Next() {
		var email string
		var name string
		var avatar string
		var avg float64
		var count int

		if err := rows.Scan(&email, &name, &avatar, &avg, &count); err != nil {
			continue
		}

		list = append(list, map[string]interface{}{
			"rank":        rank,
			"email":       email,
			"name":        name,
			"avatar":      avatar,
			"avg_score":   avg,
			"total_tests": count,
		})
		rank++
	}

	jsonResponse(w, 200, map[string]interface{}{
		"leaderboard": list,
	})
}

// ---------- REFRESH / LOGOUT ----------

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if corsWithOrigin(w, r) { return }

	ip := getIP(r)
	if !checkRateLimit("refresh:"+ip, 10, 5*time.Minute) {
		jsonResponse(w, 429, map[string]interface{}{"error": "Too many requests"})
		return
	}

	refresh := r.FormValue("refresh")

	var userID int
	err := db.QueryRow(
		"SELECT user_id FROM refresh_tokens WHERE token=$1 AND expires_at > NOW()",
		refresh,
	).Scan(&userID)

	if err != nil {
		jsonResponse(w, 401, map[string]interface{}{"error": "invalid refresh"})
		return
	}

	_, err = db.Exec("DELETE FROM refresh_tokens WHERE token=$1", refresh)
	if err != nil {
		log.Println("DB error:", err)
	}

	newRefresh := generateRefreshToken()

	_, err = db.Exec(
		"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1,$2,$3)",
		userID, newRefresh, time.Now().Add(72*time.Hour),
	)
	if err != nil {
		log.Println("DB error:", err)
	}

	var email string
	db.QueryRow("SELECT email FROM users WHERE id=$1", userID).Scan(&email)

	newToken, _ := generateJWT(email)

	jsonResponse(w, 200, map[string]interface{}{
		"token":   newToken,
		"refresh": newRefresh,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value("userEmail").(string)

	var userID int
	if err := db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&userID); err != nil {
		jsonResponse(w, 500, map[string]interface{}{"error": "User not found"})
		return
	}

	refresh := r.FormValue("refresh")

	if _, err := db.Exec("DELETE FROM refresh_tokens WHERE token=$1 AND user_id=$2", refresh, userID); err != nil {
		log.Println("DB error:", err)
	}

	jsonResponse(w, 200, map[string]interface{}{
		"status": "logged out",
	})
}

// ---------- MY RANK ----------

func myRankHandler(w http.ResponseWriter, r *http.Request) {

	email := r.Context().Value("userEmail").(string)

	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE email=$1", email).Scan(&userID)
	if err != nil {
		jsonResponse(w, 500, map[string]interface{}{"error": "User not found"})
		return
	}

	row := db.QueryRow(`
SELECT rank FROM (
	SELECT u.id,
	       RANK() OVER (ORDER BY COALESCE(AVG(t.percent),0) DESC, COUNT(t.id) DESC) as rank
	FROM users u
	LEFT JOIN test_results t ON u.id = t.user_id
	WHERE u.verified = true
	GROUP BY u.id
) ranked
WHERE id = $1
`, userID)

	var rank int
	err = row.Scan(&rank)
	if err != nil {
		jsonResponse(w, 500, map[string]interface{}{"error": "Rank not found"})
		return
	}

	jsonResponse(w, 200, map[string]interface{}{
		"rank": rank,
	})
}

// ---------- MAIN ----------

func main() {
	godotenv.Load()

	jwtSecret = []byte(os.Getenv("JWT_SECRET"))

	initDB()

	http.HandleFunc("/api/auth/send-code", sendCodeHandler)
	http.HandleFunc("/api/auth/verify-code", verifyCodeHandler)
	http.HandleFunc("/api/auth/register", registerHandler)
	http.HandleFunc("/api/auth/login", loginHandler)
	http.HandleFunc("/api/auth/me", meHandler)

	http.HandleFunc("/api/profile", authMiddleware(profileHandler))

	http.HandleFunc("/api/tests/add", authMiddleware(addResultHandler))
	http.HandleFunc("/api/tests/list", authMiddleware(getResultsHandler))

	http.HandleFunc("/api/stats", authMiddleware(statsHandler))
	http.HandleFunc("/api/leaderboard", authMiddleware(leaderboardHandler))
	http.HandleFunc("/api/my-rank", authMiddleware(myRankHandler))
	http.HandleFunc("/api/refresh", refreshHandler)
	http.HandleFunc("/api/logout", authMiddleware(logoutHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("Server running on", port)
	http.ListenAndServe(":"+port, nil)
}
