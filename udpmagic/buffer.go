package udpmagic

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxUDPConnection = 8
const udpBufSize = 64*1024 - 16
const udpTableSize = 65536

type GlobalUDPBufferTable map[[16]byte](*udpBufferNode)

type udpBufferNode struct {
	Chan        chan udpDataBlock
	WG          sync.WaitGroup
	ExitSignals []chan bool
	Lock        sync.Mutex
	timeout     time.Duration
}

func makeUDPBufferNode(timeout time.Duration) udpBufferNode {
	return udpBufferNode{
		Chan:        make(chan udpDataBlock, maxUDPConnection*2),
		WG:          sync.WaitGroup{},
		ExitSignals: make([]chan bool, 0),
		Lock:        sync.Mutex{},
		timeout:     timeout,
	}
}

type udpDataBlock struct {
	Data     []byte
	Size     uint32
	BlockId  uint32
	DestAddr net.Addr // UDP目标地址
	SrcAddr  net.Addr // UDP源地址
}

func (dataBlock udpDataBlock) Pack() []byte {
	destAddrBytes := []byte(dataBlock.DestAddr.String())
	srcAddrBytes := []byte(dataBlock.SrcAddr.String())

	headerSize := 16 + len(destAddrBytes) + len(srcAddrBytes) // 4+4+4+4 + addr lengths
	packedData := make([]byte, headerSize+int(dataBlock.Size))

	offset := 0
	binary.LittleEndian.PutUint32(packedData[offset:], dataBlock.BlockId)
	offset += 4
	binary.LittleEndian.PutUint32(packedData[offset:], dataBlock.Size)
	offset += 4
	binary.LittleEndian.PutUint32(packedData[offset:], uint32(len(destAddrBytes)))
	offset += 4
	binary.LittleEndian.PutUint32(packedData[offset:], uint32(len(srcAddrBytes)))
	offset += 4

	copy(packedData[offset:], destAddrBytes)
	offset += len(destAddrBytes)
	copy(packedData[offset:], srcAddrBytes)
	offset += len(srcAddrBytes)
	copy(packedData[offset:], dataBlock.Data)

	return packedData
}

func UnpackUDPDataBlock(data []byte) (*udpDataBlock, error) {
	if len(data) < 16 {
		return nil, errors.New("data too short")
	}

	offset := 0
	blockId := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	size := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	destAddrLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4
	srcAddrLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	if len(data) < int(16+destAddrLen+srcAddrLen+size) {
		return nil, errors.New("data too short")
	}

	destAddrStr := string(data[offset : offset+int(destAddrLen)])
	offset += int(destAddrLen)
	srcAddrStr := string(data[offset : offset+int(srcAddrLen)])
	offset += int(srcAddrLen)

	destAddr, _ := net.ResolveUDPAddr("udp", destAddrStr)
	srcAddr, _ := net.ResolveUDPAddr("udp", srcAddrStr)

	blockData := make([]byte, size)
	copy(blockData, data[offset:offset+int(size)])

	return &udpDataBlock{
		Data:     blockData,
		Size:     size,
		BlockId:  blockId,
		DestAddr: destAddr,
		SrcAddr:  srcAddr,
	}, nil
}

// Create a new key-value and return the key
func (gbt *GlobalUDPBufferTable) New(timeout time.Duration) [16]byte {
	var key [16]byte
	for {
		io.ReadFull(rand.Reader, key[:])
		if _, exist := (*gbt)[key]; !exist {
			bufferNode := makeUDPBufferNode(timeout)
			(*gbt)[key] = &bufferNode
			return key
		}
	}
}

// Delete a key-value
func (gbt *GlobalUDPBufferTable) Free(key [16]byte) {
	if _, ok := (*gbt)[key]; !ok {
		return
	}
	delete(*gbt, key)
}

func joinUDPBlocks(inData, outData chan udpDataBlock, exitSignal, taskFinish chan bool) {
	table := make(map[uint32]udpDataBlock)
	var pointer uint32 = 0
	for {
		select {
		case db := <-inData:
			table[db.BlockId%udpTableSize] = db
			if pointer != db.BlockId%udpTableSize {
				continue
			}
			for {
				if d, exist := table[pointer]; exist {
					outData <- d
					delete(table, pointer)
					pointer = (pointer + 1) % udpTableSize
					continue
				}
				break
			}
		case s := <-exitSignal:
			if s {
				return
			}
			for {
				select {
				case db := <-inData:
					table[db.BlockId%udpTableSize] = db
					if pointer != db.BlockId%udpTableSize {
						continue
					}
					for {
						if d, exist := table[pointer]; exist {
							outData <- d
							delete(table, pointer)
							pointer = (pointer + 1) % udpTableSize
							continue
						}
						break
					}
				default:
					taskFinish <- true
					return
				}
			}
		}
	}
}

func udpBlockJoiner() (chan udpDataBlock, chan udpDataBlock, chan bool, chan bool) {
	dataBlocks := make(chan udpDataBlock, maxUDPConnection*2)
	continuousData := make(chan udpDataBlock, maxUDPConnection*2)
	exitJoinBlock := make(chan bool, 2)
	finishSignal := make(chan bool, 2)
	go joinUDPBlocks(dataBlocks, continuousData, exitJoinBlock, finishSignal)
	return dataBlocks, continuousData, exitJoinBlock, finishSignal
}
