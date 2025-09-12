package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/go-sql-driver/mysql"
)

// Vulnerable Go code examples

func sqlInjectionVuln(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", "user:pass@/dbname")

	// SQL Injection - direct string concatenation
	userID := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + userID
	rows, _ := db.Query(query)
	defer rows.Close()
}

func xssVuln(w http.ResponseWriter, r *http.Request) {
	// XSS - direct output without escaping
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func commandInjectionVuln(w http.ResponseWriter, r *http.Request) {
	// Command injection
	filename := r.URL.Query().Get("file")
	cmd := exec.Command("cat", filename)
	output, _ := cmd.Output()
	w.Write(output)
}

func pathTraversalVuln(w http.ResponseWriter, r *http.Request) {
	// Path traversal
	file := r.URL.Query().Get("file")
	content, _ := os.ReadFile("uploads/" + file)
	w.Write(content)
}

func hardcodedSecrets() {
	// Hardcoded secrets
	password := "admin123456"
	apiKey := "sk-1234567890abcdef1234567890abcdef"

	fmt.Println(password, apiKey)
}

func weakCrypto() {
	// Weak cryptography - should use bcrypt or similar
	password := "userpassword"
	hash := md5.Sum([]byte(password))
	fmt.Printf("%x", hash)
}

func insecureRandom() {
	// Insecure random - should use crypto/rand
	sessionToken := rand.Intn(1000000)
	fmt.Println(sessionToken)
}

// Race condition vulnerability
var counter int

func incrementCounter() {
	// Race condition - no synchronization
	counter++
}

func main() {
	http.HandleFunc("/user", sqlInjectionVuln)
	http.HandleFunc("/hello", xssVuln)
	http.HandleFunc("/cat", commandInjectionVuln)
	http.HandleFunc("/file", pathTraversalVuln)

	http.ListenAndServe(":8080", nil)
}
