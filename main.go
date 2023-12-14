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

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
type dnsAnswer struct {
	name        string
	recordType  string
	recordClass string
	TTL         int
	RDLength    string
	RDData      int
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

func bytesToUint16(bytes []byte) uint16 {
	if len(bytes) != 2 {
		panic("Slice of invalid length passed to function, can not convert to uint16")
	}

	return uint16(bytes[0])<<8 | uint16(bytes[1])
}

func unpackReturnMessage(message []byte) string {
	// The header is the first 12 bytes 
	headerbytes := message[:12]
	fmt.Println("Response Header Bytes:", headerbytes)

	returnHeader := dnsHeader{
		id:              bytesToUint16(headerbytes[:2]),
		flags:           bytesToUint16(headerbytes[2:4]),
		numQuestions:    bytesToUint16(headerbytes[4:6]),
		numAnswers:      bytesToUint16(headerbytes[6:8]),
		numAuthorityRR:  bytesToUint16(headerbytes[8:10]),
		numAdditionalRR: bytesToUint16(headerbytes[10:12]),
	}

	fmt.Println("number of answers (expected two):", returnHeader.numAnswers)
	fmt.Println("number of questions (expect one): ", returnHeader.numQuestions)
	fmt.Println("ID of message (this is the ID we hard code):", returnHeader.id)
	fmt.Println("ID of numAuthorityRR (expect 0):", returnHeader.numAuthorityRR)
	fmt.Println("number of numAdditionalRR (expect 0):", returnHeader.numAdditionalRR)

	// check QR bit is set from flags it will be the first bit in the 16bits that make up flags
	// we know if flags is larger than 2^15-1 the first bit is set (I think...) as 2^15-1 == 32767
	if returnHeader.flags < 32767 {
		panic("No response from DNS server")
	}

	// The question is the encoded host we sent so to work out the question bytes in the response its the length of our initial question + 4
	// as a domain must always end with a 0 padding byte to indicate the end of the domain for example 
	// 3dns6google3com0 -> [3 100 110 115 6 103 111 111 103 108 101 3 99 111 109 0] we can find the first 0 byte at the end of the domain
	returnQuestionInitial := message[12:]
	shift := returnQuestionInitial[0]
	questionBytes := 0

	for shift != 0 {
		questionBytes += int(shift) + 1
		shift = returnQuestionInitial[questionBytes]
	}

	questionBytes += 5 // We need to add the 0 padding byte at the end of the domain and the 4 extra bytes

	question := message[12:(12 + questionBytes)]


	returnDNSQuestion := dnsQuestion{
		qName: question[:len(question)  - 4],
		qType: bytesToUint16(question[len(question)- 4:len(question) - 2]),
		qClass: bytesToUint16(question[len(question)- 2:]),
	}

	fmt.Println(returnDNSQuestion.qName, returnDNSQuestion.qType, returnDNSQuestion.qClass)

	return ""
}

func sendMessage(message []byte) []byte {
	addr := net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 64)

	_, err = conn.Write(message)
	if err != nil {
		log.Fatal(err)
	}

	n, err := conn.Read(buf)

	if err != nil {
		log.Fatal(err)
	}

	return (buf[:n])
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

	fmt.Println("Sending bytes:", message)

	response := sendMessage(message)

	fmt.Println("Response bytes:", response)

	unpackedResponse := unpackReturnMessage(response)

	fmt.Println(unpackedResponse)

}
