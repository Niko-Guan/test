package block

import(
		"fmt"
		"bytes"
		"encoding/binary"
		//"reflect"
		"time"
		

		"functional-master"
		"helpers-master"
	)

type BlockSlice []Block
	
type Block struct {
	BlockHeader BlockHeader
	Signature []byte
	TransactionSlice *TransactionSlice
}

type BlockHeader struct {
	Origin     []byte
	PrevBlock  []byte
	MerkelRoot []byte
	Timestamp  time.Time
	Nonce      uint32
}



func NewBlock(previousBlock []byte) Block{

	kp := GenerateNewKeypair()
	var b Block
	b.BlockHeader.Origin = (*kp).Public /*euqal to the kepair Public*//*should be stable?*/
	b.BlockHeader.PrevBlock = previousBlock /*previousBlock's hash*/
	//b.BlockHeader.MerkelRoot = GenerateMerkelRoot()
	b.BlockHeader.Timestamp = time.Now().UTC()
	b.BlockHeader.Nonce = b.GenerateNonce(helpers.ArrayOfBytes(1,0))/*(TEST_TRANSACTION_POW_COMPLEXITY, TEST_POW_PREFIX)*/
	
	b.Signature = b.Sign(kp)
	
	return b
}

func (b *Block)Hash() []byte{
	headerHash,_ := b.BlockHeader.MarshalBinary()
	return helpers.SHA256(headerHash)
}

func (b *Block) Sign(keypair *Keypair) []byte {

	s, _ := keypair.Sign(b.Hash())
	return s
}

func (b *Block)GenerateNonce(prefix []byte) uint32{
	newB := b
	
	for{
		if CheckProofOfWork(prefix, newB.Hash()){
			break
		}
		newB.BlockHeader.Nonce++
	}
	
	return newB.BlockHeader.Nonce
	
}

func (bh *BlockHeader)MarshalBinary() ([]byte, error){
	buf := new(bytes.Buffer)
	
	buf.Write(helpers.FitBytesInto(bh.Origin, 80))/*NETWORK_KEY_SIZE*/
	binary.Write(buf, binary.LittleEndian, bh.Timestamp)
	buf.Write(helpers.FitBytesInto(bh.PrevBlock, 32))/*NETWORK_KEY_SIZE*/
	buf.Write(helpers.FitBytesInto(bh.MerkelRoot,32))/*NETWORK_KEY_SIZE*/
	binary.Write(buf, binary.LittleEndian, bh.Nonce)
	
	return buf.Bytes(), nil
}

func (b *Block) GenerateMerkelRoot() []byte {

	var merkell func(hashes [][]byte) []byte
	merkell = func(hashes [][]byte) []byte {

		l := len(hashes)
		if l == 0 {
			return nil
		}
		if l == 1 {
			return hashes[0]
		} else {

			if l%2 == 1 {
				return merkell([][]byte{merkell(hashes[:l-1]), hashes[l-1]})
			}

			bs := make([][]byte, l/2)
			for i, _ := range bs {
				j, k := i*2, (i*2)+1
				bs[i] = helpers.SHA256(append(hashes[j], hashes[k]...))
			}
			return merkell(bs)
		}
	}

	ts := functional.Map(func(t Transaction) []byte { return t.Hash() }, []Transaction(*b.TransactionSlice)).([][]byte)
	return merkell(ts)
}

func (bs BlockSlice) PreviousBlock() *Block {
	l := len(bs)
	if l == 0 {
		return nil
	} else {
		return &bs[l-1]
	}
}

func (bl *BlockSlice) CreateNewBlock() Block {

	prevBlock := bl.PreviousBlock()
	prevBlockHash := []byte{}
	if prevBlock != nil {

		prevBlockHash = prevBlock.Hash()
	}

	b := NewBlock(prevBlockHash)
	//b.BlockHeader.Origin = Core.Keypair.Public

	return b
}

func (b *Block)GetInfo(){

	fmt.Println("b.BlockHeader.Origin:",b.BlockHeader.Origin)
	fmt.Println("b.BlockHeader.PrevBlock:",b.BlockHeader.PrevBlock)
	fmt.Println("b.BlockHeader.MerkelRoot:",b.BlockHeader.MerkelRoot)
	fmt.Println("b.BlockHeader.Timestamp:",b.BlockHeader.Timestamp)
	fmt.Println("b.BlockHeader.Nonce:",b.BlockHeader.Nonce)
	fmt.Println("b.Signature:",b.Signature)
}