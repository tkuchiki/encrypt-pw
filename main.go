package main

import (
	"errors"
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/bgentry/speakeasy"
	"github.com/jeramey/go-pwhash/md5_crypt"
	"github.com/jeramey/go-pwhash/sha256_crypt"
	"github.com/jeramey/go-pwhash/sha512_crypt"
	"gopkg.in/alecthomas/kingpin.v2"
	"math/rand"
	"time"
)

const (
	RoundsMin = 1000
	RoundsMax = 999999999
)

func IsInvalidHash(h string) bool {
	return !(h == "sha512" || h == "sha256" || h == "md5")
}

func IsInvalidRounds(r int, h string) bool {
	if h == "md5" {
		return false
	}

	return (r < RoundsMin || r > RoundsMax)
}

func InputPassword() (passwd string, err error) {
	passwd, err = speakeasy.Ask("Enter password: ")

	if err != nil {
		return passwd, err
	}

	if passwd == "" {
		return passwd, errors.New("Empty password")
	}

	return passwd, err
}

func ConfirmPassword() (passwd string, err error) {
	passwd, err = InputPassword()

	if err != nil {
		return passwd, err
	}

	passwd2, err := speakeasy.Ask("Enter same password again: ")
	if err != nil {
		return passwd, err
	}

	if passwd != passwd2 {
		err = errors.New("Password do not match")
	}

	return passwd, err
}

func MD5Crypt(password string) string {
	rand.Seed(time.Now().UnixNano())
	salt := md5_crypt.GenerateSalt(8)

	return md5_crypt.Crypt(password, salt)
}

func Sha256Crypt(password string, rounds int) string {
	rand.Seed(time.Now().UnixNano())
	salt := sha256_crypt.GenerateSalt(16, rounds)

	return sha256_crypt.Crypt(password, salt)
}

func Sha512Crypt(password string, rounds int) string {
	rand.Seed(time.Now().UnixNano())
	salt := sha512_crypt.GenerateSalt(16, rounds)

	return sha512_crypt.Crypt(password, salt)
}

var (
	hash     = kingpin.Flag("hash", "Hash algorithm (sha512, sha256, md5)").Default("sha512").Short('h').String()
	rounds   = kingpin.Flag("rounds", fmt.Sprintf("Number of hashing rounds (min: %d, max: %d)", RoundsMin, RoundsMax)).Default("5000").Short('r').Int()
	confirm  = kingpin.Flag("confirm", "Confirm password").Short('c').Bool()
	password = kingpin.Flag("password", "Password").Short('p').String()
)

func main() {
	kingpin.CommandLine.Help = "Encrypts password (starts from $1$, $5$, $6$ hash)"
	kingpin.Version("0.0.1")
	kingpin.Parse()

	var pass string
	var err error
	log := logrus.New()

	if IsInvalidHash(*hash) {
		log.Fatal("Invalid hash algorithm")
	}

	if IsInvalidRounds(*rounds, *hash) {
		log.Fatal(fmt.Sprintf("Invalid rounds (%d - %d)", RoundsMin, RoundsMax))
	}

	if *password != "" {
		pass = *password
	} else if *confirm {
		pass, err = ConfirmPassword()
		if err != nil {
			log.Fatal(err)
		}
	} else {
		pass, err = InputPassword()
		if err != nil {
			log.Fatal(err)
		}
	}

	switch *hash {
	case "sha512":
		fmt.Println(Sha512Crypt(pass, *rounds))
	case "sha256":
		fmt.Println(Sha256Crypt(pass, *rounds))
	case "md5":
		fmt.Println(MD5Crypt(pass))
	}
}
