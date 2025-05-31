package udpmagic

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// UDP Magic configuration
type UDPMagicConfig struct {
	MaxConnections int
	Timeout        time.Duration
	BufferSize     int
	EnableLogging  bool
}

// Default UDP Magic configuration
var DefaultUDPMagicConfig = UDPMagicConfig{
	MaxConnections: 8,
	Timeout:        30 * time.Second,
	BufferSize:     64 * 1024,
	EnableLogging:  false,
}

// UDP Magic Manager
type UDPMagicManager struct {
	config    UDPMagicConfig
	bufTable  GlobalUDPBufferTable
	mutex     sync.RWMutex
	logFunc   func(f string, v ...interface{})
	connPools map[string][]net.PacketConn
}

// Create new UDP Magic Manager
func NewUDPMagicManager(config UDPMagicConfig) *UDPMagicManager {
	if config.MaxConnections <= 0 {
		config.MaxConnections = DefaultUDPMagicConfig.MaxConnections
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultUDPMagicConfig.Timeout
	}
	if config.BufferSize <= 0 {
		config.BufferSize = DefaultUDPMagicConfig.BufferSize
	}

	manager := &UDPMagicManager{
		config:    config,
		bufTable:  make(GlobalUDPBufferTable),
		connPools: make(map[string][]net.PacketConn),
		logFunc:   func(f string, v ...interface{}) {}, // Default no-op logger
	}

	if config.EnableLogging {
		manager.logFunc = func(f string, v ...interface{}) {
			fmt.Printf("[UDPMagic] "+f+"\n", v...)
		}
	}

	return manager
}

// Set custom log function
func (m *UDPMagicManager) SetLogFunc(logFunc func(f string, v ...interface{})) {
	m.logFunc = logFunc
}

// Create UDP Magic Local (Client side)
func (m *UDPMagicManager) CreateUDPMagicLocal(localAddr, remoteAddr string, shadow func(net.PacketConn) net.PacketConn) error {
	localConn, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", localAddr, err)
	}

	if shadow != nil {
		localConn = shadow(localConn)
	}

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		localConn.Close()
		return fmt.Errorf("failed to resolve remote address %s: %v", remoteAddr, err)
	}

	// Create connection factory for child connections
	createConn := func(dataKey [16]byte) net.PacketConn {
		childConn, err := net.ListenPacket("udp", "")
		if err != nil {
			m.logFunc("Failed to create child connection: %v", err)
			return nil
		}
		if shadow != nil {
			childConn = shadow(childConn)
		}
		return childConn
	}

	m.logFunc("Starting UDP Magic Local: %s -> %s", localAddr, remoteAddr)
	go UDPRelayLocal(localConn, remoteUDPAddr, createConn, m.config.Timeout)

	return nil
}

// Create UDP Magic Remote (Server side)
func (m *UDPMagicManager) CreateUDPMagicRemote(listenAddr string, shadow func(net.PacketConn) net.PacketConn) error {
	mainConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}

	if shadow != nil {
		mainConn = shadow(mainConn)
	}

	m.logFunc("Starting UDP Magic Remote on: %s", listenAddr)

	go func() {
		buf := make([]byte, m.config.BufferSize)
		for {
			n, clientAddr, err := mainConn.ReadFrom(buf)
			if err != nil {
				m.logFunc("Error reading from main connection: %v", err)
				continue
			}

			// Check if this is a key request (magic byte 0xFF)
			if n == 1 && buf[0] == 0xFF {
				// Handle main connection for this client
				go UDPRelayRemoteMain(mainConn, clientAddr, &m.bufTable, m.config.Timeout, m.logFunc)
			} else if n == 17 && len(buf) >= 17 {
				// Check if this is a child connection with data key
				var dataKey [16]byte
				copy(dataKey[:], buf[1:17])

				// Create child connection
				childConn, err := net.ListenPacket("udp", "")
				if err != nil {
					m.logFunc("Failed to create child connection: %v", err)
					continue
				}
				if shadow != nil {
					childConn = shadow(childConn)
				}

				go UDPRelayRemoteChild(childConn, dataKey, &m.bufTable, m.config.Timeout, m.logFunc)
			}
		}
	}()

	return nil
}

// Get connection pool for a specific remote address
func (m *UDPMagicManager) getConnectionPool(remoteAddr string) []net.PacketConn {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.connPools[remoteAddr]
}

// Create connection pool for a remote address
func (m *UDPMagicManager) createConnectionPool(localAddr, remoteAddr string, shadow func(net.PacketConn) net.PacketConn) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.connPools[remoteAddr]; exists {
		return nil // Pool already exists
	}

	conns := make([]net.PacketConn, 0, m.config.MaxConnections)
	for i := 0; i < m.config.MaxConnections; i++ {
		conn, err := net.ListenPacket("udp", localAddr)
		if err != nil {
			// Close previously created connections
			for _, c := range conns {
				c.Close()
			}
			return fmt.Errorf("failed to create connection %d: %v", i, err)
		}

		if shadow != nil {
			conn = shadow(conn)
		}

		conns = append(conns, conn)
	}

	m.connPools[remoteAddr] = conns
	return nil
}

// Close connection pool for a remote address
func (m *UDPMagicManager) closeConnectionPool(remoteAddr string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if conns, exists := m.connPools[remoteAddr]; exists {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
		delete(m.connPools, remoteAddr)
	}
}

// Close all connection pools
func (m *UDPMagicManager) Close() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for remoteAddr, conns := range m.connPools {
		for _, conn := range conns {
			if conn != nil {
				conn.Close()
			}
		}
		delete(m.connPools, remoteAddr)
	}
}
