package udpmagic

import (
	"net"
	"time"
)

// UDP client relay with magic multiple connections support
func UDPRelayLocal(localConn net.PacketConn, remoteAddr net.Addr, createConn func([16]byte) net.PacketConn, timeout time.Duration) {
	// Create a special packet to request data key
	keyRequestPacket := make([]byte, 1)
	keyRequestPacket[0] = 0xFF // Magic byte for key request

	// Send key request to remote
	_, err := localConn.WriteTo(keyRequestPacket, remoteAddr)
	if err != nil {
		return
	}

	// Read data key from remote
	var dataKey [16]byte
	keyBuf := make([]byte, 17) // 1 byte magic + 16 bytes key
	n, _, err := localConn.ReadFrom(keyBuf)
	if err != nil || n != 17 || keyBuf[0] != 0xFE {
		return
	}
	copy(dataKey[:], keyBuf[1:])

	dataBlocks, continuousData, exitJoinBlock, joinBlockfinish := udpBlockJoiner()
	defer func() { exitJoinBlock <- true }()

	exitThreadMan := udpThreadManager(createConn, dataBlocks, dataKey, timeout)
	recvExit, exitRecv := udpBufferFromRemote(localConn, dataBlocks, remoteAddr, timeout)
	sendExit, exitSend := udpDataBlockToConn(localConn, continuousData, timeout)

	leave := func() {
		if udpConn, ok := localConn.(*net.UDPConn); ok {
			udpConn.SetDeadline(time.Now())
		}
		exitRecv <- true
		exitSend <- true
		exitThreadMan <- true
	}

	select {
	case <-sendExit:
		leave()
		return
	case <-recvExit:
		// Wait for data process finished or leave
		exitThreadMan <- true
		exitJoinBlock <- false
		exitSend <- false
		<-joinBlockfinish
		<-sendExit
	}
	return
}

func udpRelayLocalChild(createConn func([16]byte) net.PacketConn, dataBlocks chan udpDataBlock, dataKey [16]byte, remoteAddr net.Addr, timeout time.Duration, exit chan bool) {
	conn := createConn(dataKey)
	if conn == nil {
		return
	}
	defer conn.Close()
	taskExit, exitSignal := udpBufferFromRemote(conn, dataBlocks, remoteAddr, timeout)
	for {
		select {
		case <-taskExit:
			return
		case e := <-exit:
			exitSignal <- e
			return
		}
	}
}

// UDP Connection Manager: create connections every 1 second until Max.
func udpThreadManager(createConn func([16]byte) net.PacketConn, dataBlocks chan udpDataBlock, dataKey [16]byte, timeout time.Duration) chan bool {
	exitSignal := make(chan bool, 2)
	go func() {
		exitSignals := make([]chan bool, 0)
		// We need remoteAddr for child connections, but we'll get it from the first packet
		var remoteAddr net.Addr

		// Wait a bit to get the remote address from first packet
		<-time.After(time.Duration(time.Millisecond) * 100)

		for {
			select {
			case <-time.After(time.Duration(time.Millisecond) * 1000):
				currentConn := len(exitSignals)
				for i := currentConn; i < maxUDPConnection && i < currentConn+2; i++ {
					exitS := make(chan bool, 2)
					exitSignals = append(exitSignals, exitS)
					go udpRelayLocalChild(createConn, dataBlocks, dataKey, remoteAddr, timeout, exitS)
				}
			case eSignal := <-exitSignal:
				for _, s := range exitSignals {
					s <- eSignal
				}
				return
			}
		}
	}()
	return exitSignal
}

// Write UDP dataBlock to connection
func udpDataBlockToConn(conn net.PacketConn, db chan udpDataBlock, timeout time.Duration) (chan bool, chan bool) {
	taskExit := make(chan bool, 2)
	exitSignal := make(chan bool, 2)
	go func() {
		for {
			select {
			case data := <-db:
				if udpConn, ok := conn.(*net.UDPConn); ok {
					udpConn.SetWriteDeadline(time.Now().Add(timeout))
				}
				_, err := conn.WriteTo(data.Data, data.DestAddr)
				if err != nil {
					taskExit <- true
					return
				}
			case s := <-exitSignal:
				if s {
					return
				}
				for {
					select {
					case data := <-db:
						if udpConn, ok := conn.(*net.UDPConn); ok {
							udpConn.SetWriteDeadline(time.Now().Add(timeout))
						}
						_, err := conn.WriteTo(data.Data, data.DestAddr)
						if err != nil {
							taskExit <- true
							return
						}
					default:
						return
					}
				}
			}
		}
	}()
	return taskExit, exitSignal
}
