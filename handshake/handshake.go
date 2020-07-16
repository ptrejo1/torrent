package handshake

import (
	"fmt"
	"io"
)

// Handshake is a special message peer uses to indentify itself
type Handshake struct {
	Pstr     string
	InfoHash [20]byte
	PeerID   [20]byte
}

// Serialize serializes the handshake to buffer
func (h *Handshake) Serialize() []byte {
	buffer := make([]byte, len(h.Pstr)+49)
	buffer[0] = byte(len(h.Pstr))
	curr := 1
	curr += copy(buffer[curr:], h.Pstr)
	curr += copy(buffer[curr:], make([]byte, 8))
	curr += copy(buffer[curr:], h.InfoHash[:])
	curr += copy(buffer[curr:], h.PeerID[:])

	return buffer
}

// Read parses a handshake from stream
func Read(r io.Reader) (*Handshake, error) {
	lengthBuffer := make([]byte, 1)
	_, err := io.ReadFull(r, lengthBuffer)
	if err != nil {
		return nil, err
	}

	pstrlen := int(lengthBuffer[0])
	if pstrlen == 0 {
		err := fmt.Errorf("psrtlen can't be 0")
		return nil, err
	}

	handshakeBuf := make([]byte, 48+pstrlen)
	_, err = io.ReadFull(r, handshakeBuf)
	if err != nil {
		return nil, err
	}

	var infoHash, peerID [20]byte
	copy(infoHash[:], handshakeBuf[pstrlen+8:pstrlen+8+20])
	copy(peerID[:], handshakeBuf[pstrlen+8+20:])

	h := Handshake{
		Pstr:     string(handshakeBuf[0:pstrlen]),
		InfoHash: infoHash,
		PeerID:   peerID,
	}

	return &h, nil
}

// New creates a new handshake w/ standard pstr
func New(infoHash, peerID [20]byte) *Handshake {
	return &Handshake{
		Pstr:     "BitTorrent protocol",
		InfoHash: infoHash,
		PeerID:   peerID,
	}
}
