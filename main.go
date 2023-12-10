package main

import (
	"fmt"
	"math/rand"
	"strings"
)

// DNS question format as defined by RFC1035 4.1.2 -> https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type dnsQuestion struct {
	QNAME  []byte
	QTYPE  int //https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
	QCLASS int //https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
}

// Static host for now to work out resolving logic, add ability for this to be passed in later
const host string = "dns.google.com"

func generateQueryID() int {
	// 65535 is the largest number we can represent in 16bits (=2^16–1)
	return rand.Intn(65535)
}

func encodeHost(host string) []byte {
	// Produces an encoded string under the following format - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	// QNAME = dns.google.com -> 3dns6google3com0 -> [3 100 110 115 6 103 111 111 103 108 101 3 99 111 109 0]

	result := []byte{}

	for _, section := range strings.Split(host, ".") {
		result = append(result, byte(len(section)))
		result = append(result, []byte(section)...)
	}

	// Append final 0 to represent end of domain name
	result = append(result, byte(0))

	return result
}

func main() {
	// Generate query ID that must be represented in 16bits defined by ID - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
	queryId := generateQueryID()
	fmt.Println("Query ID:", queryId)

	// Encode the hostname to standard defined by QNAME - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	encodedHost := encodeHost(host)
	fmt.Println(encodedHost)

	// Build out a static question for now
	sendingQuestion := dnsQuestion{
		QNAME:  encodedHost, 
		QTYPE:  1, // A Record
		QCLASS: 1, // INTERNET
	}

	fmt.Println(sendingQuestion.QCLASS, sendingQuestion.QNAME, sendingQuestion.QTYPE)
}
