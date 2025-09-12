package main

import (
    "fmt"
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

func vulnerableQuery(userInput string) {
    db, _ := sql.Open("mysql", "user:password@/dbname")
    // Vulnerable: Direct string concatenation in SQL query
    query := "SELECT * FROM users WHERE name = '" + userInput + "'"
    rows, _ := db.Query(query)
    defer rows.Close()
}

func main() {
    fmt.Println("Demo application")
    vulnerableQuery("admin")
}
