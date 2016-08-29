package main

import (
	"golang.org/x/crypto/bcrypt"
	//"fmt"
	"bufio"
	"flag"
	"os"
)

const DefaultCost = 12

/*
Read a password from StdIn. Write a valid hash to Stdout.

If a hash is passed as a command line argument, verify the password
against the hash and exit with status code 1 if it doesn't match.
Supress the output of a new hash unless it needs to be upgraded.
*/
func main() {
	var cost int
	flag.IntVar(&cost, "c", DefaultCost, "hashing cost (>=12 recommended)")
	flag.Parse()
	args := flag.Args()

	scanner := bufio.NewScanner(os.Stdin)

	if len(args) == 0 {
		for scanner.Scan() {
			password := []byte(scanner.Text())
			hashedPassword, err := bcrypt.GenerateFromPassword(password, cost)
			if err != nil {
				os.Stderr.WriteString(err.Error())
			}
			os.Stdout.Write(hashedPassword)
			os.Stdout.WriteString("\n")
		}
	} else {
		for _, arg := range args {
			if !scanner.Scan() {
				break
			}
			password := []byte(scanner.Text())
			err := bcrypt.CompareHashAndPassword([]byte(arg), password)
			if err != nil {
				// XXX think of better interface for multiple args
				os.Exit(1)
			}
		}
	}
}
