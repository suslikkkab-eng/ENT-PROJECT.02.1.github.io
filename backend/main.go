package main

import (
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

type CodeData struct {
	Code      string
	ExpiresAt time.Time
	Attempts  int
}

var (
	codes      = make(map[string]CodeData)
	rateLimits = make(map[string][]time.Time)

	mu        sync.Mutex
	jwtSecret []byte
	db        *sql.DB
)

func jsonResponse(w http.ResponseWriter, status int, data map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func cors(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func getIP(r *http.Request) string {
	ip := r.Header.Get("X-Forwarded-For")
	if ip != "" {
		return strings.TrimSpace(strings.Split(ip, ",")[0])
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
		rateLimits[key] = fresh
		return false
	}

	rateLimits[key] = append(fresh, now)
	return true
}

func generateCode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", n.Int64())
}

func sendEmail(to, code string) error {
	from := os.Getenv("SMTP_EMAIL")
	pass := os.Getenv("SMTP_PASSWORD")

	if from == "" || pass == "" {
		return fmt.Errorf("SMTP_EMAIL or SMTP_PASSWORD is empty")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Код подтверждения")
	m.SetBody("text/plain", "Ваш код подтверждения: "+code+"\n\nКод действует 10 минут.")

	d := gomail.NewDialer("smtp.gmail.com", 587, from, pass)
	return d.DialAndSend(m)
}

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

	email, ok := claims["email"].(string)
	if !ok {
		return "", fmt.Errorf("email not found")
	}

	return email, nil
}

func initDB() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is empty")
	}

	var err error
	db, err = sql.Open("postgres", databaseURL)
	if err != nil {
		log.Fatal("DB open error:", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatal("DB ping error:", err)
	}

	query := `
	CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		verified BOOLEAN DEFAULT FALSE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(query); err != nil {
		log.Fatal("Create users table error:", err)
	}

	fmt.Println("PostgreSQL connected")
}

// ---------- HANDLERS ----------

func sendCodeHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "OPTIONS" {
		return
	}

	ip := getIP(r)
	if !checkRateLimit("send-code:"+ip, 2, 5*time.Minute) {
		jsonResponse(w, 429, map[string]string{"error": "Too many code requests. Try again later."})
		return
	}

	email := r.URL.Query().Get("email")
	if !strings.Contains(email, "@") {
		jsonResponse(w, 400, map[string]string{"error": "Invalid email"})
		return
	}

	code := generateCode()

	mu.Lock()
	codes[email] = CodeData{
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Attempts:  0,
	}
	mu.Unlock()

	if err := sendEmail(email, code); err != nil {
		log.Println("Email error:", err)
		jsonResponse(w, 500, map[string]string{"error": "Failed to send email"})
		return
	}

	jsonResponse(w, 200, map[string]string{"status": "code_sent"})
}

func verifyCodeHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "OPTIONS" {
		return
	}

	email := r.URL.Query().Get("email")
	code := r.URL.Query().Get("code")

	mu.Lock()
	defer mu.Unlock()

	data, ok := codes[email]
	if !ok {
		jsonResponse(w, 400, map[string]string{"error": "Code not found"})
		return
	}

	if time.Now().After(data.ExpiresAt) {
		delete(codes, email)
		jsonResponse(w, 400, map[string]string{"error": "Code expired"})
		return
	}

	if data.Attempts >= 5 {
		delete(codes, email)
		jsonResponse(w, 429, map[string]string{"error": "Too many attempts"})
		return
	}

	if data.Code != code {
		data.Attempts++
		codes[email] = data
		jsonResponse(w, 400, map[string]string{"error": "Invalid code"})
		return
	}

	delete(codes, email)

	_, err := db.Exec("UPDATE users SET verified = TRUE WHERE email = $1", email)
	if err != nil {
		log.Println("Verify DB error:", err)
	}

	jsonResponse(w, 200, map[string]string{"status": "verified"})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "OPTIONS" {
		return
	}

	ip := getIP(r)
	if !checkRateLimit("register:"+ip, 3, 5*time.Minute) {
		jsonResponse(w, 429, map[string]string{"error": "Too many register attempts. Try again later."})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		jsonResponse(w, 400, map[string]string{"error": "Missing fields"})
		return
	}

	if len(password) < 6 {
		jsonResponse(w, 400, map[string]string{"error": "Password must be at least 6 characters"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "Password hash error"})
		return
	}

	_, err = db.Exec(
		"INSERT INTO users (email, password_hash, verified) VALUES ($1, $2, FALSE)",
		email,
		string(hash),
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			jsonResponse(w, 400, map[string]string{"error": "User already exists"})
			return
		}
		log.Println("Register DB error:", err)
		jsonResponse(w, 500, map[string]string{"error": "Database error"})
		return
	}

	jsonResponse(w, 200, map[string]string{"status": "registered"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "OPTIONS" {
		return
	}

	ip := getIP(r)
	if !checkRateLimit("login:"+ip, 5, 5*time.Minute) {
		jsonResponse(w, 429, map[string]string{"error": "Too many login attempts. Try again later."})
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	var passwordHash string
	var isVerified bool

	err := db.QueryRow(
		"SELECT password_hash, verified FROM users WHERE email = $1",
		email,
	).Scan(&passwordHash, &isVerified)

	if err == sql.ErrNoRows {
		jsonResponse(w, 400, map[string]string{"error": "Invalid credentials"})
		return
	}

	if err != nil {
		log.Println("Login DB error:", err)
		jsonResponse(w, 500, map[string]string{"error": "Database error"})
		return
	}

	if !isVerified {
		jsonResponse(w, 403, map[string]string{"error": "Email not verified"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		jsonResponse(w, 400, map[string]string{"error": "Invalid credentials"})
		return
	}

	token, err := generateJWT(email)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "Token error"})
		return
	}

	jsonResponse(w, 200, map[string]string{
		"status": "login_success",
		"token":  token,
	})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	cors(w)
	if r.Method == "OPTIONS" {
		return
	}

	auth := r.Header.Get("Authorization")
	if auth == "" {
		jsonResponse(w, 401, map[string]string{"error": "No token"})
		return
	}

	tokenStr := strings.Replace(auth, "Bearer ", "", 1)
	email, err := parseJWT(tokenStr)
	if err != nil {
		jsonResponse(w, 401, map[string]string{"error": "Invalid token"})
		return
	}

	jsonResponse(w, 200, map[string]string{"email": email})
}

// ---------- MAIN ----------

func main() {
	_ = godotenv.Load()

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is empty")
	}
	jwtSecret = []byte(secret)

	initDB()

	http.HandleFunc("/api/auth/send-code", sendCodeHandler)
	http.HandleFunc("/api/auth/verify-code", verifyCodeHandler)
	http.HandleFunc("/api/auth/register", registerHandler)
	http.HandleFunc("/api/auth/login", loginHandler)
	http.HandleFunc("/api/auth/me", meHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("Server running on", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
