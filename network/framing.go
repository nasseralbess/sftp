// network/framing.go
package network

import (
	"encoding/binary"
	"fmt"
	"io"
)

const lenBytes = 4 // Use uint32 for length

// WriteMsg sends length-prefixed data to the writer.
func WriteMsg(writer io.Writer, data []byte) error {
	if writer == nil {
		return fmt.Errorf("writer is nil")
	}
	msgLen := uint32(len(data))
	lenBuf := make([]byte, lenBytes)
	binary.BigEndian.PutUint32(lenBuf, msgLen)

	// Write length prefix
	n, err := writer.Write(lenBuf)
	if err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}
	if n != lenBytes {
		return fmt.Errorf("short write for message length (%d/%d bytes)", n, lenBytes)
	}

	// Write actual message data
	n, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}
	if n != int(msgLen) {
		return fmt.Errorf("short write for message data (%d/%d bytes)", n, msgLen)
	}

	return nil
}

// ReadMsg reads length-prefixed data from the reader.
func ReadMsg(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("reader is nil")
	}
	lenBuf := make([]byte, lenBytes)

	// Read length prefix
	_, err := io.ReadFull(reader, lenBuf)
	if err != nil {
		// EOF is common when connection closes, handle it specifically if needed upstream
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)

	// Basic sanity check for length (e.g., prevent huge allocation)
	// Adjust max length as needed for your protocol constraints
	const maxMessageSize = 10 * 1024 * 1024 // 10 MB limit
	if msgLen > maxMessageSize {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", msgLen, maxMessageSize)
	}
	if msgLen == 0 {
		return []byte{}, nil // Handle zero-length message explicitly if needed
	}

	// Read actual message data
	msgData := make([]byte, msgLen)
	_, err = io.ReadFull(reader, msgData)
	if err != nil {
		return nil, fmt.Errorf("failed to read message data (length %d): %w", msgLen, err)
	}

	return msgData, nil
}
