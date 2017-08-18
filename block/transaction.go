package block

import(
	"fmt"
	"time"
	"bytes"
	"encoding/binary"
	
	
	"helpers-master"
	
)



type Transaction struct {
	Header    TransactionHeader
	Signature []byte
	Payload   string
}

type TransactionHeader struct {
	From          string
	To            string
	Timestamp     time.Time
	PayloadHash   []byte
	PayloadLength uint32
	Nonce         uint32
}

type TransactionSlice []Transaction


func NewTransaction(From, To, Payload string) Transaction{

	kp := GenerateNewKeypair()
	
	var tr Transaction
	tr.Header.From = From
	tr.Header.To = To
	tr.Header.Timestamp = time.Now().UTC()
	
	tr.Signature = tr.Sign(kp)
	tr.Payload = Payload
	
	tr.Header.PayloadHash = helpers.SHA256([]byte(Payload))
	tr.Header.PayloadLength = uint32(len(tr.Payload))
	tr.Header.Nonce = tr.GenerateNonce(helpers.ArrayOfBytes(1,0))/*(TEST_TRANSACTION_POW_COMPLEXITY, TEST_POW_PREFIX)*/
	
	return tr
}

func (th *TransactionHeader) MarshalBinary()([]byte, error){
	buf := new(bytes.Buffer)
	
	buf.Write(helpers.FitBytesInto([]byte(th.From), 80))/*NETWORK_KEY_SIZE*/
	buf.Write(helpers.FitBytesInto([]byte(th.To), 80))/*NETWORK_KEY_SIZE*/
	binary.Write(buf, binary.LittleEndian, th.Timestamp)
	buf.Write(helpers.FitBytesInto(th.PayloadHash, 32))
	binary.Write(buf, binary.LittleEndian, th.PayloadLength)
	binary.Write(buf, binary.LittleEndian, th.Nonce)
	
	return buf.Bytes(), nil
}

func (t *Transaction)Hash() []byte{
	headerBytes,_ := t.Header.MarshalBinary()
	return helpers.SHA256(headerBytes)
}

func (t *Transaction)Sign(keypair *Keypair) []byte{
	s,_ := keypair.Sign(t.Hash())
	return s
}

func (t *Transaction)GenerateNonce(prefix []byte) uint32{
	newT :=t
	for{
		if CheckProofOfWork(prefix, newT.Hash()){
			break
		}
		newT.Header.Nonce++
	}
	return newT.Header.Nonce
}

func (slice TransactionSlice) AddTransaction(t Transaction) TransactionSlice {

	// Inserted sorted by timestamp
	for i, tr := range slice {
		if tr.Header.Timestamp.Unix() >= t.Header.Timestamp.Unix() {
			return append(append(slice[:i], t), slice[i:]...)
		}
	}

	return append(slice, t)
}

func (tr *Transaction)GetInfo() {
	fmt.Println("tr.Header.From:",tr.Header.From)
	fmt.Println("tr.Header.To:",tr.Header.To)
	fmt.Println("tr.Header.Timestamp:",tr.Header.Timestamp)
	fmt.Println("tr.Header.PayloadHash:",tr.Header.PayloadHash)
	fmt.Println("tr.Header.PayloadLength:",tr.Header.PayloadLength)
	fmt.Println("tr.Header.Nonce:",tr.Header.Nonce)
	fmt.Println("tr.Signature:",tr.Signature)
	fmt.Println("tr.Payload:",tr.Payload)
}