package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/joho/godotenv"
)

func seedAccount(store Storage, fname, lname, pw string) *Account {
	acc, err := NewAccount(fname, lname, pw)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}

	fmt.Println("new account => ", acc.Number)

	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "tunde", "rammy", "rammy88888")
}

func main() {

	seed := flag.Bool("seed", false, "seed the db")

	flag.Parse()
	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Init(); err != nil {
		log.Fatal(err)

	}
	godotenv.Load()

	// seed
	if *seed {
		fmt.Println("Seeding the db")
		seedAccounts(store)
	}

	server := NewAPIServer(":8000", store)
	server.Run()
	fmt.Println("Yeah")
}
