package sftp

import (
  "encoding/binary"
  "errors"
  "io"
)

// Message types
const (
  AuthRequest         byte = 0x01
  AuthResponse        byte = 0x02
  FileListRequest     byte = 0x03
  FileListResponse    byte = 0x04
  FileUploadRequest   byte = 0x05
  FileDownloadRequest byte = 0x06
  DataPacket          byte = 0x07
  TransferStatus      byte = 0x08
  Error               byte = 0xFF
)

// Message represents a protocol message
type Message struct {
  Type     byte
  Sequence uint32
  Payload  []byte
}

// NewMessage creates a new message with given type, sequence number, and payload
func NewMessage(msgType byte, sequence uint32, payload []byte) *Message {
  return &Message{
    Type:     msgType,
    Sequence: sequence,
    Payload:  payload,
  }
}

// Encode serializes a message to a byte slice
func (m *Message) Encode() ([]byte, error) {
  // Message format:
  // - Length (4 bytes)
  // - Type (1 byte)
  // - Sequence (4 bytes)
  // - Payload (variable)
  // Calculate total message length
  // 4 bytes for length field + 1 byte for type + 4 bytes for sequence + payload length
  totalLength := 4 + 1 + 4 + len(m.Payload)
  // Create buffer for serialized message
  buf := make([]byte, totalLength)
  // Write length (excluding the length field itself)
  binary.BigEndian.PutUint32(buf[0:4], uint32(1+4+len(m.Payload)))
  // Write type
  buf[4] = m.Type
  // Write sequence
  binary.BigEndian.PutUint32(buf[5:9], m.Sequence)
  // Write payload
  copy(buf[9:], m.Payload)
  return buf, nil
}

// Decode deserializes a message from a reader
func DecodeMessage(reader io.Reader) (*Message, error) {
  // Read length field (4 bytes)
  lenBuf := make([]byte, 4)
  if _, err := io.ReadFull(reader, lenBuf); err != nil {
    return nil, err
  }
  length := binary.BigEndian.Uint32(lenBuf)
  if length < 5 { // Minimum message size: 1 byte type + 4 bytes sequence
    return nil, errors.New("invalid message length")
  }
  // Read the rest of the message
  msgBuf := make([]byte, length)
  if _, err := io.ReadFull(reader, msgBuf); err != nil {
    return nil, err
  }
  // Extract type
  msgType := msgBuf[0]
  // Extract sequence
  sequence := binary.BigEndian.Uint32(msgBuf[1:5])
  // Extract payload
  payload := msgBuf[5:]
  return &Message{
    Type:     msgType,
    Sequence: sequence,
    Payload:  payload,
  }, nil
}
