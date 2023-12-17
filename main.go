package main

import (
	"encoding/binary"
	"errors"
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
	packedFields := packUint16Fields(fieldsToPack)
	return packedFields
}

func (header *dnsHeader) checkResponse() error {
	var err error
	// check QR bit is set from flags it will be the first bit in the 16bits that make up flags
	// we know if flags is larger than 2^15-1 the first bit is set (I think...) as 2^15-1 == 32767
	if header.flags < 32767 {
		err = errors.New("No response from DNS server")
	}
	return err
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

// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
type resourceRecordIPv4 struct {
	// name is a compressed field see - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
	name        string
	recordType  uint16
	recordClass uint16
	// This will be how long we want to hold this data in memory for at some point so repeated resolutions do not do an upstream expensive network call
	TTL      uint32
	RDLength uint16
	RDData   net.IP
}

type resourceRecordNS struct {
	// name is a compressed field see - https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
	name        string
	recordType  uint16
	recordClass uint16
	TTL         uint32
	RDLength    uint16
	RDData      string
}

func packUint16Fields(fields []uint16) []byte {
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

func domainLength(message []byte) int {
	shift := message[0]
	domainBytes := 0

	for shift != 0 {
		domainBytes += int(shift) + 1
		shift = message[domainBytes]
	}
	
	domainBytes++ // removes 0 pad
	return domainBytes
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

func decodeHost(encodedHost []byte) string {
	var valueShifts []int
	var domainParts []string

	shift := encodedHost[0]
	fqdnBytes := 0

	for shift != 0 {
		valueShifts = append(valueShifts, int(shift))
		fqdnBytes += int(shift) + 1
		shift = encodedHost[fqdnBytes]
	}

	sliceStart := 1

	for _, valueShift := range valueShifts {
		domainParts = append(domainParts, string(encodedHost[sliceStart:valueShift+sliceStart]))
		sliceStart = sliceStart + valueShift + 1
	}

	return strings.Join(domainParts, ".")
}

func decodeIP(IP []byte) net.IP {
	return net.IPv4(IP[0], IP[1], IP[2], IP[3])
}

func uint16ToByteSlice(number uint16) []byte {
	// uint16 is represented in 2 bytes
	buf := make([]byte, 2)

	binary.BigEndian.PutUint16(buf, number)

	return buf
}

func unpackResponseHeader(message []byte) dnsHeader {
	// The header is the first 12 bytes
	headerBytes := message[:12]

	returnHeader := dnsHeader{
		id:              binary.BigEndian.Uint16(headerBytes[:2]),
		flags:           binary.BigEndian.Uint16(headerBytes[2:4]),
		numQuestions:    binary.BigEndian.Uint16(headerBytes[4:6]),
		numAnswers:      binary.BigEndian.Uint16(headerBytes[6:8]),
		numAuthorityRR:  binary.BigEndian.Uint16(headerBytes[8:10]),
		numAdditionalRR: binary.BigEndian.Uint16(headerBytes[10:12]),
	}

	return returnHeader
}

func extractAuthorityAnswer(message []byte) []byte {
	message = message[domainLength(message) + 4:]
	return message
}

func unpackAuthorityAnswer(message []byte, answer []byte) resourceRecordNS {
	// If the number is bigger than 49152 we know the first two bits are set and the message is compressed.
	if binary.BigEndian.Uint16(answer[0:2]) > 49152 {
		referenceDomain := binary.BigEndian.Uint16(answer[0:2]) - 49152 // The shift of bytes  from start of the message the source domain this is our pointer.

		fqdnInitial := message[referenceDomain:]

		shift := fqdnInitial[0]
		fqdnBytes := 0

		for shift != 0 {
			fqdnBytes += int(shift) + 1
			shift = message[12+fqdnBytes]
		}

		fqdn := message[referenceDomain : (int(referenceDomain)+int(fqdnBytes))+1]

		answerResourceRecord := resourceRecordNS{
			name:        decodeHost(fqdn),
			recordType:  binary.BigEndian.Uint16(answer[2:4]),
			recordClass: binary.BigEndian.Uint16(answer[4:6]),
			TTL:         binary.BigEndian.Uint32(answer[6:10]),
			RDLength:    binary.BigEndian.Uint16(answer[10:12]),
			RDData:      decodeHost(answer[12 : 12+binary.BigEndian.Uint16(answer[10:12])]),
		}

		return answerResourceRecord
	}
	return resourceRecordNS{}
}

// refactor this function to use domainLength() to work out how many bytes the domain is domainLength should also return to the domain bytes
func extractAnswers(message []byte, responseAnswers int) [][]byte {
	var answers [][]byte

	// The question is the encoded host we sent so to work out the question bytes in the response its the length of our initial question + 4
	// as a domain must always end with a 0 padding byte to indicate the end of the domain for example
	// 3dns6google3com0 -> [3 100 110 115 6 103 111 111 103 108 101 3 99 111 109 0] we can find the first 0 byte at the end of the domain
	returnQuestionInitial := message
	shift := returnQuestionInitial[0]
	questionBytes := 0

	for shift != 0 {
		questionBytes += int(shift) + 1
		shift = returnQuestionInitial[questionBytes]
	}

	questionBytes += 5 // We need to add the 0 padding byte at the end of the domain and the 4 extra bytes containing the IPv4 address

	initialAnswer := message[questionBytes:]

	separator := len(initialAnswer)/responseAnswers - 1
	count := 0
	part := 0

	for index := range initialAnswer {
		if count == separator {
			answers = append(answers, initialAnswer[part:index+1])
			count = 0
			part += separator + 1
			continue
		}

		count += 1
	}

	return answers
}

func unpackAnswers(message []byte, answers [][]byte) []resourceRecordIPv4 {
	var resourceRecords []resourceRecordIPv4

	for _, answer := range answers {

		// If the number is bigger than 49152 we know the first two bits are set and the message is compressed.
		if binary.BigEndian.Uint16(answer[0:2]) > 49152 {
			referenceDomain := binary.BigEndian.Uint16(answer[0:2]) - 49152 // The shift of bytes  from start of the message the source domain this is our pointer.

			fqdnInitial := message[referenceDomain:]

			shift := fqdnInitial[0]
			fqdnBytes := 0

			for shift != 0 {
				fqdnBytes += int(shift) + 1
				shift = message[12+fqdnBytes]
			}

			fqdn := message[referenceDomain : (int(referenceDomain)+int(fqdnBytes))+1]

			answerResourceRecord := resourceRecordIPv4{
				name:        decodeHost(fqdn),
				recordType:  binary.BigEndian.Uint16(answer[2:4]),
				recordClass: binary.BigEndian.Uint16(answer[4:6]),
				TTL:         binary.BigEndian.Uint32(answer[6:10]),
				RDLength:    binary.BigEndian.Uint16(answer[10:12]),
				RDData:      decodeIP(answer[12 : 12+binary.BigEndian.Uint16(answer[10:12])]),
			}

			resourceRecords = append(resourceRecords, answerResourceRecord)
		}
	}

	return resourceRecords
}

func sendMessage(message []byte) []byte {
	addr := net.UDPAddr{
		IP:   net.IPv4(198, 41, 0, 4),
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
		id:              22, // static for now but will need to be unique later call generateQueryID()
		flags:           0,  // Turn off the recursion bit meaning we need to do a recursive resolve
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

	response := sendMessage(message)

	responseHeader := unpackResponseHeader(response)
	responseNoHeader := response[12:]
	err := responseHeader.checkResponse()
	if err != nil {
		log.Fatal(err)
	}

	if responseHeader.numAnswers == 0 && responseHeader.numAuthorityRR > 0 {
		authorityAnswer := extractAuthorityAnswer(responseNoHeader)
		unpackedAuthorityAnswer := unpackAuthorityAnswer(response, authorityAnswer)

		fmt.Println(unpackedAuthorityAnswer.RDData)

	} else {
		answers := extractAnswers(responseNoHeader, int(responseHeader.numAnswers))

		unpackedResponses := unpackAnswers(response, answers)

		for _, unpackedResponse := range unpackedResponses {
			fmt.Println("Domain -", unpackedResponse.name, "IPv4 -", unpackedResponse.RDData)
		}
	}
}
