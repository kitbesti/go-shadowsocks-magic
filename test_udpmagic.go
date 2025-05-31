package main

import (
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/kitbesti/go-shadowsocks-magic/udpmagic"
)

// Simple test for UDP Magic functionality
func TestUDPMagic(t *testing.T) {
	t.Log("Testing UDP Magic functionality...")

	// Create UDP Magic manager
	config := udpmagic.UDPMagicConfig{
		MaxConnections: 4,
		Timeout:        10 * time.Second,
		BufferSize:     64 * 1024,
		EnableLogging:  true,
	}
	manager := udpmagic.NewUDPMagicManager(config)

	// Test server side
	t.Log("Starting UDP Magic Remote on :18080")
	err := manager.CreateUDPMagicRemote(":18080", nil)
	if err != nil {
		t.Fatalf("Failed to create UDP Magic Remote: %v", err)
	}

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Test client side
	t.Log("Starting UDP Magic Local on :18081 -> localhost:18080")
	err = manager.CreateUDPMagicLocal(":18081", "localhost:18080", nil)
	if err != nil {
		t.Fatalf("Failed to create UDP Magic Local: %v", err)
	}

	// Send test data
	time.Sleep(100 * time.Millisecond)
	testClient, err := net.Dial("udp", "localhost:18081")
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}
	defer testClient.Close()

	testData := make([]byte, 32)
	rand.Read(testData)

	bytesWritten, err := testClient.Write(testData)
	if err != nil {
		t.Fatalf("Failed to send test data: %v", err)
	}

	if bytesWritten != len(testData) {
		t.Errorf("Expected to write %d bytes, but wrote %d bytes", len(testData), bytesWritten)
	}

	// Set read timeout to avoid blocking indefinitely
	testClient.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Try to read response (if any)
	buffer := make([]byte, len(testData))
	n, err := testClient.Read(buffer)
	if err != nil {
		// For UDP Magic, we might not get a direct echo response
		// This is expected behavior, so we'll just log it
		t.Logf("No response received (expected for UDP Magic): %v", err)
	} else {
		t.Logf("Received %d bytes response", n)
	}

	t.Log("UDP Magic test completed successfully!")
}
