package udpmagic

import (
	"errors"
	"net"
	"time"
)

// UDP server relay main connection - handle key distribution and data aggregation
func UDPRelayRemoteMain(localConn net.PacketConn, remoteAddr net.Addr, GBT *GlobalUDPBufferTable, timeout time.Duration, logf func(f string, v ...interface{})) {
	k := GBT.New(timeout)
	defer GBT.Free(k)

	// Send data key to client
	keyResponsePacket := make([]byte, 17) // 1 byte magic + 16 bytes key
	keyResponsePacket[0] = 0xFE           // Magic byte for key response
	copy(keyResponsePacket[1:], k[:])
	_, err := localConn.WriteTo(keyResponsePacket, remoteAddr)
	if err != nil {
		return
	}

	defer func() {
		// Broadcast exit(peaceful) signals to all receivers
		for _, receiver := range (*GBT)[k].ExitSignals {
			receiver <- false
		}
		// Wait for receivers exit
		(*GBT)[k].WG.Wait()
		if udpConn, ok := localConn.(*net.UDPConn); ok {
			udpConn.SetDeadline(time.Now())
		}
	}()

	go udpBufferToLocal(localConn, remoteAddr, (*GBT)[k], timeout)

	// Receive data from remote and push it to channel
	var bID uint32
	buf := make([]byte, udpBufSize)
	for bID = 0; ; bID++ {
		// Prevent id overflow
		bID = bID % udpTableSize

		if udpConn, ok := localConn.(*net.UDPConn); ok {
			udpConn.SetReadDeadline(time.Now().Add(timeout))
		}

		n, srcAddr, err := localConn.ReadFrom(buf)
		if err != nil {
			logf("Error when read remote: %s", err)
			break
		}

		// Skip magic packets (key request/response)
		if n == 1 || (n == 17 && buf[0] == 0xFE) {
			continue
		}

		dataBlock := udpDataBlock{
			Data:     make([]byte, n),
			Size:     uint32(n),
			BlockId:  bID,
			DestAddr: remoteAddr, // The original client
			SrcAddr:  srcAddr,    // The actual remote server
		}
		copy(dataBlock.Data, buf[:n])

		select {
		case (*GBT)[k].Chan <- dataBlock:
			continue
		default:
			// Channel full, drop packet or handle overflow
			logf("Buffer channel full, dropping packet")
		}
	}
	return
}

// Handle child connection for UDP relay
func UDPRelayRemoteChild(localConnChild net.PacketConn, dataKey [16]byte, GBT *GlobalUDPBufferTable, timeout time.Duration, logf func(f string, v ...interface{})) (int64, error) {
	logf("UDP child thread start")
	bufferNode, ok := (*GBT)[dataKey]
	if !ok {
		logf("dataKey invalid")
		return 0, errors.New("invalid data key")
	}
	logf("dataKey verified")

	// For child connections, we need to determine the remote address
	// This should be passed or determined from the first packet
	var remoteAddr net.Addr

	// Try to get first packet to determine remote address
	buf := make([]byte, udpBufSize)
	if udpConn, ok := localConnChild.(*net.UDPConn); ok {
		udpConn.SetReadDeadline(time.Now().Add(timeout))
	}

	_, addr, err := localConnChild.ReadFrom(buf)
	if err != nil {
		return 0, err
	}
	remoteAddr = addr

	udpBufferToLocal(localConnChild, remoteAddr, bufferNode, timeout)
	return 0, nil
}

// Relay data from GBT to local UDP connection
func udpBufferToLocal(conn net.PacketConn, remoteAddr net.Addr, bufferNode *udpBufferNode, timeout time.Duration) {
	exitSignal := make(chan bool, 2)
	bufferNode.Lock.Lock()
	bufferNode.ExitSignals = append(bufferNode.ExitSignals, exitSignal)
	bufferNode.Lock.Unlock()
	bufferNode.WG.Add(1)

	defer bufferNode.WG.Done()
	for {
		select {
		case dataBlock := <-bufferNode.Chan:
			bytes := dataBlock.Pack()
			if udpConn, ok := conn.(*net.UDPConn); ok {
				udpConn.SetWriteDeadline(time.Now().Add(timeout))
			}
			_, err := conn.WriteTo(bytes, remoteAddr)
			if err != nil {
				// Put the dataBlock back to channel for retry
				select {
				case bufferNode.Chan <- dataBlock:
				default:
					// Channel full, drop
				}
				return
			}
		case s := <-exitSignal:
			if s == false {
				// finish all tasks first before leave
				for {
					select {
					case dataBlock := <-bufferNode.Chan:
						bytes := dataBlock.Pack()
						if udpConn, ok := conn.(*net.UDPConn); ok {
							udpConn.SetWriteDeadline(time.Now().Add(timeout))
						}
						_, err := conn.WriteTo(bytes, remoteAddr)
						if err != nil {
							select {
							case bufferNode.Chan <- dataBlock:
							default:
								// Channel full, drop
							}
							return
						}
					default:
						return
					}
				}
			} else {
				// exit directly
				return
			}
		}
	}
}
