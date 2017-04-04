package main

import (
	"errors"
	"fmt"
	"bytes"
	"github.com/Sirupsen/logrus"
	"github.com/bgentry/speakeasy"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/GehirnInc/crypt/common"
	"gopkg.in/alecthomas/kingpin.v2"
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

func MD5Crypt(password string) (string, error) {
	return md5_crypt.New().Generate([]byte(password), []byte{})
}

func Sha256Crypt(password string, rounds int) (string, error) {
	salt := common.Salt{
		MagicPrefix:   []byte(sha256_crypt.MagicPrefix),
		SaltLenMin:    sha256_crypt.SaltLenMin,
		SaltLenMax:    sha256_crypt.SaltLenMax,
		RoundsDefault: sha256_crypt.RoundsDefault,
		RoundsMin:     sha256_crypt.RoundsMin,
		RoundsMax:     sha256_crypt.RoundsMax,
	}
	return sha256_crypt.New().Generate([]byte(password), salt.GenerateWRounds(sha256_crypt.SaltLenMax, rounds))
}

func Sha512Crypt(password string, rounds int) (string, error) {
	salt := common.Salt{
		MagicPrefix:   []byte(sha512_crypt.MagicPrefix),
		SaltLenMin:    sha512_crypt.SaltLenMin,
		SaltLenMax:    sha512_crypt.SaltLenMax,
		RoundsDefault: sha512_crypt.RoundsDefault,
		RoundsMin:     sha512_crypt.RoundsMin,
		RoundsMax:     sha512_crypt.RoundsMax,
	}
	return sha512_crypt.New().Generate([]byte(password), salt.GenerateWRounds(sha512_crypt.SaltLenMax, rounds))
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
		hash, err := Sha512Crypt(pass, *rounds)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
	case "sha256":
		hash, err := Sha256Crypt(pass, *rounds)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
	case "md5":
		hash, err := MD5Crypt(pass)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hash)
	}
}
