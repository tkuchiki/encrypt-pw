# encrypt-pw
Encrypts password 

## Installation

Download from https://github.com/tkuchiki/encrypt-pw/releases

## Usage

```
$ ./encrypt-pw --help
usage: encrypt-pw [<flags>]

Encrypts password (starts from $1$, $5$, $6$ hash)

Flags:
      --help               Show context-sensitive help (also try --help-long and --help-man).
      -h, --hash="sha512"      Hash algorithm (sha512, sha256, md5)
      -r, --rounds=5000        Number of hashing rounds (min: 1000, max: 999999999)
      -c, --confirm            Confirm password
      -p, --password=PASSWORD  Password
      --version            Show application version.

$ ./encrypt-pw
Enter password:
$6$eVuwo0XKesWWkbv3$/L.Sw8RJuk69aamprVSN.id2tCWJ0OiSmRJ12JNyahAdPopx7aHOWDvZ/PYustFFQ6Eu7vp22FYLqvXTUIo9I0

$ ./encrypt-pw -c
Enter password:
Enter same password again:
$6$59LB.ugo8iWh4dJf$4YjghX24znjgRC5MPF/h/f.FP8K37EiWBjmaybGWIMFTEQRPaQUDibCUcg72qRx54qW0As3GsvkCEYShEifMA.

$ ./encrypt-pw -p your-password
$6$N2UrLLeq3i3560Vv$cOC/xvVRHo1vGAJcsp788UrkUIg1Bc66.pwYRhcQFfiI4lor8SDQQKgW8zT7qdc4bflbEnkTGEyulU7v9DCcT

$ ./encrypt-pw -h sha256 -p your-password
$5$m0Q22Redjm5D7.zH$rvRH/obRUtCu9osnxxOYcg0JOTLoDpPnSLagpU9gn6B

$ ./encrypt-pw -h md5 -p your-password
$1$CaybI5OM$p3F4OZCYEmOLOCtZmmbAw1

$ ./encrypt-pw -r 100000 -p your-password
$6$rounds=100000$g9EPi5gIxSX2cpMR$UVIstanJwu4uCtNpW1HIdQmu.Y4yPm9HzVL1mcwoz0E87Gn0FI7AunYy5wOQ8FBArwlIQc6N6YZITsDW6aZZh/
```

## Build

```
$ go get
$ cp -a src/github.com/jeramey/go-pwhash/* src/antihe.ro/pwhash/`
$ go build
```

## Dependency

This software includes the work that is distributed in the Apache License 2.0.

- https://github.com/bgentry/speakeasy

This software includes the work that is distributed in the 2-clause BSD License

- https://github.com/jeramey/go-pwhash

This software includes the work that is distributed in the MIT License

- https://github.com/Sirupsen/logrus
