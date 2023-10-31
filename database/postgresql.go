package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func Postgresql() *sql.DB {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("cannot load .env file: ", err)
	}

	db, err := sql.Open("postgres", os.Getenv("postgresql"))
	if err != nil {
		panic(err.Error())
	}
	fmt.Println("Connected to PostgreSQL")
	return db
}
