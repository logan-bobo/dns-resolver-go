package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
)

// Static host for now to work out resolving logic, add ability for this to be passed in later
const host string = "dns.google.com"

// DNS question format as defined by RFC1035 4.1.2 -> https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type dnsQuestion struct {
	qName  []byte
	qType  uint16
	qClass uint16
}

func (question *dnsQuestion) packQuestion() []byte {
	var packedQuestion []byte

	packedQuestion = append(packedQuestion, question.qName...)
	packedQuestion = append(packedQuestion, uint16ToByteSlice(question.qType)...)
	packedQuestion = append(packedQuestion, uint16ToByteSlice(question.qClass)...)

	return packedQuestion
}

type dnsHeader struct {
	id              uint16
	flags           uint16
	numQuestions    uint16
	numAnswers      uint16
	numAuthorityRR  uint16
	numAdditionalRR uint16
}

func (header *dnsHeader) packHeader() []byte {
	fieldsToPack := []uint16{header.id, header.flags, header.numQuestions, header.numAnswers, header.numAuthorityRR, header.numAdditionalRR}
	packedFields := packuint16Fields(fieldsToPack)
	return packedFields
}

type dnsMessage struct {
	header   dnsHeader
	question dnsQuestion
}

func (message *dnsMessage) packMessage(header []byte, dnsQuestion []byte) []byte {
	var packedMessage []byte

	packedMessage = append(packedMessage, header...)
	packedMessage = append(packedMessage, dnsQuestion...)

	return packedMessage
}

func (message *dnsMessage) generateHex(bytes []byte) string {
	var hexString string

	hexString = hex.EncodeToString(bytes)

	return hexString
}

func packuint16Fields(fields []uint16) []byte {
	var packedFields []byte

	for _, field := range fields {
		packedFields = append(packedFields, uint16ToByteSlice(field)...)
	}

	return packedFields
}

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

func uint16ToByteSlice(number uint16) []byte {
	// uint16 is represented in 2 bytes
	slice := make([]byte, 2)
	slice[0] = byte(number >> 8)
	slice[1] = byte(number)

	return slice
}

func main() {
	// Build out a static question for now, can be dynamic later...
	sendingQuestion := dnsQuestion{
		qName:  encodeHost(host),
		qType:  1, // A Record
		qClass: 1, // INTERNET
	}

	// Build out a static message, can be dynamic later...
	sendingHeader := dnsHeader{
		id:              22,  // static for now but will need to be unique later call generateQueryID()
		flags:           256, // Setting the 'recursion desired' bit to 1 (8th bit) in uint16
		numQuestions:    1,
		numAnswers:      0,
		numAuthorityRR:  0,
		numAdditionalRR: 0,
	}

	sendingMessage := dnsMessage{
		header:   sendingHeader,
		question: sendingQuestion,
	}

	message := sendingMessage.packMessage(
		sendingHeader.packHeader(),
		sendingQuestion.packQuestion(),
	)

	hexStr := sendingMessage.generateHex(message)

	fmt.Println("Initial hex:", hexStr)

	addr := net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)

	_, err = conn.Write(message)
	if err != nil {
		log.Fatal(err)
	}

	n, err := conn.Read(buf)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Response Hex:", hex.EncodeToString(buf[:n]))
}
