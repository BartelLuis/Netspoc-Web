package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/hknutzen/Netspoc-Web/go/pkg/backend"
)

func main() {
	userDir := flag.String("user-dir", "/var/lib/policyweb/users", "directory containing local user records")
	email := flag.String("email", "", "email address used to log in")
	passwordStdin := flag.Bool("password-stdin", false, "read the password from standard input")
	flag.Parse()
	if *email == "" || !*passwordStdin || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	password, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		log.Fatal(err)
	}
	if len(password) > 4096 {
		log.Fatal("password exceeds 4096 bytes")
	}
	login := strings.ToLower(strings.TrimSpace(*email))
	if err := backend.SetUserPassword(*userDir, login, strings.TrimRight(string(password), "\r\n")); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Created or updated local user %s\n", login)
}
