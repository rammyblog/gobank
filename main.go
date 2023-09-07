package main

import (
	"fmt"
	"log"

	"github.com/joho/godotenv"
)

func main() {
	store, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Init(); err != nil {
		log.Fatal(err)

	}
	godotenv.Load()

	server := NewAPIServer(":8000", store)
	server.Run()
	fmt.Println("Yeah")
}
