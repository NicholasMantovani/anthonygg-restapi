package main

import "log"

var store *PostgresStore

// This is actually not recommended
func init() {
	s, err := NewPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := s.Init(); err != nil {
		log.Fatal(err)
	}
	//fmt.Printf("%+v\n", store)
	store = s
}

func main() {
	server := NewApiServer(":3000", store)
	server.Run()
}
