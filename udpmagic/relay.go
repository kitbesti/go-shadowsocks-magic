package udpmagic

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// Receive UDP data from the connection and convert to dataBlocks
func udpBufferFromRemote(conn net.PacketConn, dataBlocks chan udpDataBlock, remoteAddr net.Addr, timeout time.Duration) (chan bool, chan bool) {
	exitSignal := make(chan bool, 2)
	taskExit := make(chan bool)
	go func() {
		buf := make([]byte, udpBufSize+100) // Extra space for headers
		for {
			if udpConn, ok := conn.(*net.UDPConn); ok {
				udpConn.SetReadDeadline(time.Now().Add(timeout))
			}

			n, srcAddr, err := conn.ReadFrom(buf)
			if err != nil {
				break
			}

			// Skip magic packets
			if n == 1 || (n == 17 && (buf[0] == 0xFF || buf[0] == 0xFE)) {
				continue
			}

			// Try to unpack as UDP data block first
			if dataBlock, err := UnpackUDPDataBlock(buf[:n]); err == nil {
				select {
				case dataBlocks <- *dataBlock:
					continue
				case <-exitSignal:
					taskExit <- true
					return
				}
			} else {
				// Raw UDP packet, create a dataBlock
				dataBlock := udpDataBlock{
					Data:     make([]byte, n),
					Size:     uint32(n),
					BlockId:  0, // Will be set by caller
					DestAddr: remoteAddr,
					SrcAddr:  srcAddr,
				}
				copy(dataBlock.Data, buf[:n])

				select {
				case dataBlocks <- dataBlock:
					continue
				case <-exitSignal:
					taskExit <- true
					return
				}
			}
		}
		taskExit <- true
	}()
	return taskExit, exitSignal
}

// Convert raw UDP packets to dataBlocks with proper addressing
func udpPacketToDataBlock(data []byte, srcAddr, destAddr net.Addr, blockId uint32) udpDataBlock {
	return udpDataBlock{
		Data:     data,
		Size:     uint32(len(data)),
		BlockId:  blockId,
		DestAddr: destAddr,
		SrcAddr:  srcAddr,
	}
}

// Read UDP metadata and payload
func readUDPMetadata(data []byte) (blockId, size, destAddrLen, srcAddrLen uint32, err error) {
	if len(data) < 16 {
		err = errors.New("insufficient data for UDP metadata")
		return
	}

	blockId = binary.LittleEndian.Uint32(data[0:4])
	size = binary.LittleEndian.Uint32(data[4:8])
	destAddrLen = binary.LittleEndian.Uint32(data[8:12])
	srcAddrLen = binary.LittleEndian.Uint32(data[12:16])

	return
}

// Extract address strings from UDP packet
func extractUDPAddresses(data []byte, offset int, destAddrLen, srcAddrLen uint32) (destAddr, srcAddr net.Addr, newOffset int, err error) {
	if len(data) < offset+int(destAddrLen)+int(srcAddrLen) {
		err = errors.New("insufficient data for addresses")
		return
	}

	destAddrStr := string(data[offset : offset+int(destAddrLen)])
	offset += int(destAddrLen)
	srcAddrStr := string(data[offset : offset+int(srcAddrLen)])
	offset += int(srcAddrLen)

	destAddr, _ = net.ResolveUDPAddr("udp", destAddrStr)
	srcAddr, _ = net.ResolveUDPAddr("udp", srcAddrStr)
	newOffset = offset

	return
}

// Handle UDP packet forwarding with load balancing across multiple connections
func udpForwardWithLoadBalancing(sourceConn net.PacketConn, targetConns []net.PacketConn, packet []byte, destAddr net.Addr) error {
	if len(targetConns) == 0 {
		return errors.New("no target connections available")
	}

	// Simple round-robin load balancing
	connIndex := int(time.Now().UnixNano()) % len(targetConns)
	targetConn := targetConns[connIndex]

	_, err := targetConn.WriteTo(packet, destAddr)
	return err
}

// Create UDP connection pool for magic relay
func createUDPConnectionPool(localAddr string, size int) ([]net.PacketConn, error) {
	conns := make([]net.PacketConn, 0, size)

	for i := 0; i < size; i++ {
		conn, err := net.ListenPacket("udp", localAddr)
		if err != nil {
			// Close previously created connections
			for _, c := range conns {
				c.Close()
			}
			return nil, err
		}
		conns = append(conns, conn)
	}

	return conns, nil
}

// Close UDP connection pool
func closeUDPConnectionPool(conns []net.PacketConn) {
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}
}
