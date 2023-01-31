package mlstreamer

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type Network uint

const (
	Ethereum          Network = 1
	BinanceSmartChain Network = 56
)

type Streamer struct {
	m sync.Mutex

	KeyId     string
	KeySecret string
	Network   Network

	active bool

	subs []func(txb []byte, noticed, propagated time.Time)

	queuedMessages []struct {
		b   []byte
		ret chan error
	}

	conn   net.Conn
	ctx    context.Context
	cancel context.CancelFunc
}

//Creates a streamer with a userId and keyId, which you can retrieve from the
//mevlink website.
func NewStreamer(keyId, keySecret string, network Network) *Streamer {
	var ret Streamer
	ret.KeyId = keyId
	ret.KeySecret = keySecret
	ret.Network = network
	return &ret
}

//Provides a callback giving RLP-encoded transaction bytes when they are
//received. See the Stream() function code for a detailed description of the
//noticed and propagated times.
func (s *Streamer) OnTransaction(f func(txb []byte, noticed, propagated time.Time)) {
	s.m.Lock()
	s.subs = append(s.subs, f)
	s.m.Unlock()
}

func (s *Streamer) _send(msg []byte) error {
	var idx = 0
	for idx < len(msg) {
		if n, err := s.conn.Write(msg[idx:]); err != nil {
			return errors.Wrap(err, "error sending b")
		} else {
			idx += n
		}
	}
	return nil
}

func (s *Streamer) send(msg []byte) error {
	s.m.Lock()
	if s.active {
		s.m.Unlock()
		return errors.New("no active connection; haven't yet begun streaming")
	} else {
		if s.conn == nil {
			var c = make(chan error)
			s.queuedMessages = append(s.queuedMessages, struct {
				b   []byte
				ret chan error
			}{
				b:   msg,
				ret: c,
			})
			s.m.Unlock()
			return <-c
		} else {
			err := s._send(msg)
			s.m.Unlock()
			return err
		}
	}
}

//Tell Mevlink to broadcast an RLP-encoded transaction.
func (s *Streamer) EmitTransaction(txb []byte) error {
	return errors.Wrap(s.send(append([]byte{EMIT_TRANSACTION}, txb...)), "error emitting tx")
}

func (s *Streamer) Stream() error {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.active = true
	defer func() {
		s.active = false
	}()
	for {
		if disconnect_id, err := s._stream(); err != nil {
			log.Println("mevlink streaming error: " + err.Error() + "; reconnecting in one second...")
		} else if disconnect_id >= 0 {
			switch disconnect_id {
			case DISCONNECT_UNKNOWN_USER:
				return errors.New("couldn't authenticate to the server; api key ID doesn't exist")
			case DISCONNECT_BAD_MAC:
				return errors.New("couldn't authenticate to the server; api key ID exists but password is incorrect")
			case DISCONNECT_TOO_MANY_CONNECTIONS:
				return errors.New("couldn't authenticate to the server; api key ID exists but password is incorrect")
			case DISCONNECT_PROTOCOL_ERROR:
				return errors.New("this client was disconnected for making a protocol error; is it the latest version/have you made modifications?")
			case DISCONNECT_INTERNAL_SERVER_ERROR:
				log.Println("disconnected from server for internal server error; attempting to reconnect")
			default:
				log.Println("got unknown disconnect id of ", disconnect_id)
			}
		} else {
			return nil
		}
		time.Sleep(time.Second)
	}
}

func (s *Streamer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

const (
	DISCONNECT_UNKNOWN_USER int = iota
	DISCONNECT_TOO_MANY_CONNECTIONS
	DISCONNECT_PROTOCOL_ERROR
	DISCONNECT_INTERNAL_SERVER_ERROR
	DISCONNECT_BAD_MAC
)

//Begins the streaming process and starts making callbacks to functions
//provided in OnTransaction. Automatically attempts to reconnect. Errors if the
//connection handshake fails despite a backoff.
func (s *Streamer) _stream() (int, error) {
	conn, mac, err := s.connect()
	if err != nil {
		return 0, errors.Wrap(err, "error connecting outright")
	}

	s.m.Lock()
	s.conn = conn
	for _, v := range s.queuedMessages {
		if err := s._send(v.b); err != nil {
			v.ret <- err
		} else {
			v.ret <- nil
		}
	}
	s.queuedMessages = s.queuedMessages[0:0]
	s.m.Unlock()
	defer func() {
		s.m.Lock()
		s.conn.Close()
		s.conn = nil
		for _, v := range s.queuedMessages {
			v.ret <- errors.New("connection closed")
		}
		s.queuedMessages = s.queuedMessages[0:0]
		s.m.Unlock()
	}()

	//Now we are authenticated and the server should start sending TRANSACTION messages.
	for {
		select {
		case <-s.ctx.Done():
			return -1, nil
		default:
		}
		msg_id, err := readUntilFull(1, conn)
		if err != nil {
			return -1, errors.Wrap(err, "error reading msg id byte")
		}
		switch msg_id[0] {
		case TRANSACTION:
			//Each transaction message includes three things: the encoded
			//transaction, an 8 byte unix microsecond timestamp indicating when the
			//transaction was sent, and another 8 byte unix microsecond timestamp
			//indicating when mevlink first learned about the transaction. Both
			//timestamps are big-endian encoded.

			//All transactions in the ethereumplex include a length specifier near the
			//beginning. BSC uses legacy transactions and so are rlp encoded.
			//See: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
			tx, err := readUntilFull(1, conn)
			if err != nil {
				return 0, errors.Wrap(err, "error reading tx ln header")
			}
			var remaining int

			if tx[0] > 0x80 && tx[0] < 0xb8 {
				remaining = int(tx[0] - 0x80)
			} else if tx[0] > 0xb7 && tx[0] < 0xc0 {
				var ln_of_ln = tx[0] - 0xb7
				if i_b, err := readUntilFull(int(ln_of_ln), conn); err != nil {
					return -1, errors.Wrap(err, "error reading ln of ln")
				} else {
					tx = append(tx, i_b...)
					remaining = int(binary.BigEndian.Uint64(append(make([]byte, 8-len(i_b)), i_b...)))
				}
			} else if tx[0] > 0xc0 && tx[0] < 0xf8 {
				remaining = int(tx[0] - 0xc0)
			} else if tx[0] > 0xf7 {
				var ln_of_ln = tx[0] - 0xf7
				if i_b, err := readUntilFull(int(ln_of_ln), conn); err != nil {
					return -1, errors.Wrap(err, "error reading ln of ln")
				} else {
					tx = append(tx, i_b...)
					remaining = int(binary.BigEndian.Uint64(append(make([]byte, 8-len(i_b)), i_b...)))
				}
			} else {
				log.Fatal("bad transaction data; got ln of ", tx[0])
			}

			if txb, err := readUntilFull(remaining, conn); err != nil {
				return -1, errors.Wrap(err, "error reading tx bytes")
			} else {
				tx = append(tx, txb...)
			}

			//Now that you have the transaction, you can either respond to it
			//immediately or wait for timing information and MAC indicating it hasn't
			//been tampered with and is recent enough to act upon.

			//Next is the "propagated" timestamp. This is a unix microsecond
			//timestamp of when the mevlink relay received and sent us the
			//transaction.
			propagated_b, err := readUntilFull(8, conn)
			if err != nil {
				return -1, errors.Wrap(err, "error reading propagation bytes")
			}
			propagated := time.UnixMicro(int64(binary.BigEndian.Uint64(propagated_b)))

			//Finally, we have the "noticed" timestamp. This gives the earliest time
			//mevlink heard of the transaction's existence from other peers on BSC.
			//Note that this may not be the earliest time *any* mevlink relay has
			//heard about the transaction at time of sending.
			noticed_b, err := readUntilFull(8, conn)
			if err != nil {
				return -1, errors.Wrap(err, "error reading noticed bytes")
			}
			noticed := time.UnixMicro(int64(binary.BigEndian.Uint64(noticed_b)))

			//Finally, the mac
			given_mac, err := readUntilFull(32, conn)
			if err != nil {
				return -1, errors.Wrap(err, "error reading mac")
			}
			mac.Reset()
			mac.Write(msg_id)
			mac.Write(tx)
			mac.Write(propagated_b)
			mac.Write(noticed_b)
			if bytes.Compare(given_mac, mac.Sum(nil)) != 0 {
				return -1, errors.New("mac was incorrect")
			} else {
				s.m.Lock()
				subs := append([]func(txb []byte, noticed, propagated time.Time){}, s.subs...)
				s.m.Unlock()
				for _, f := range subs {
					f(tx, noticed, propagated)
				}
			}
		default:
			return -1, errors.New("unknown message id")
		}
	}
}

func (s *Streamer) connect() (net.Conn, hash.Hash, error) {
	var streaming_ip_loc string
	if provided_host := os.Getenv("MEVLINK_HOST"); provided_host == "" {
		streaming_ip_loc = "https://mevlink.com/api/"
	} else {
		streaming_ip_loc = provided_host + "/api/"
	}

	var get_node_ips_path string
	switch s.Network {
	case Ethereum:
		get_node_ips_path = "get_eth_node_ips"
	case BinanceSmartChain:
		get_node_ips_path = "get_bsc_node_ips"
	default:
		return nil, nil, errors.New("Unsupported network")
	}

	streaming_ip_loc += get_node_ips_path

	resp, err := http.Get(streaming_ip_loc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error requesting mevlink relay ips")
	}

	var ips []string
	if err := json.NewDecoder(resp.Body).Decode(&ips); err != nil {
		return nil, nil, errors.Wrap(err, "error decoding mevlink relay response")
	}

	//TODO: Connect to all and then pick based on actual tx receive time instead of tcp latency
	var bestLatency time.Duration = time.Second
	var bestConn net.Conn
	for _, ip := range ips {
		startedAt := time.Now()
		conn, err := net.Dial("tcp", ip+":25568")
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not connect to server at "+ip)
		}
		delay := time.Now().Sub(startedAt)
		if delay < bestLatency {
			bestLatency = delay
			bestConn = conn
		} else if err := conn.Close(); err != nil {
			return nil, nil, errors.Wrap(err, "error closing rejected streaming connection at "+ip)
		}
	}
	if bestConn == nil {
		return nil, nil, errors.New("no servers active or couldn't get acceptable latency; check your connection")
	}

	//Send hello message with protocol version and user id
	hello := make([]byte, 1+1+16)
	hello[0] = HELLO                          //Message ID
	hello[1] = 0x00                           //Only valid protocol version for now
	user_id_b, _ := hex.DecodeString(s.KeyId) //(Sample user id)
	copy(hello[1+1:1+1+16], user_id_b)

	if _, err := bestConn.Write(hello); err != nil {
		bestConn.Close()
		return nil, nil, errors.Wrap(err, "error writing HELLO message")
	}

	//Read challenge
	challenge_msg_b, err := readUntilFull(1+16, bestConn)
	if err != nil {
		bestConn.Close()
		return nil, nil, errors.Wrap(err, "error reading challenge bytes; bad user ID?")
	}
	if challenge_msg_b[0] != CHALLENGE {
		bestConn.Close()
		return nil, nil, errors.Wrap(err, "error reading challenge bytes; bad message id; internal server error")
	}
	challenge_b := challenge_msg_b[1 : 1+16]

	//Write hmac response
	challenge_response := make([]byte, 1+32)
	challenge_response[0] = CHALLENGE_RESPONSE

	secret_b, _ := hex.DecodeString(s.KeySecret)
	var mac = hmac.New(sha256.New, secret_b)
	mac.Write(challenge_b)
	copy(challenge_response[1:1+32], mac.Sum(nil))
	mac.Reset()

	if _, err := bestConn.Write(challenge_response); err != nil {
		bestConn.Close()
		return nil, nil, errors.Wrap(err, "error writing challenge-response message")
	}
	return bestConn, mac, nil
}

//Current message ids as of protocol version 0
const (
	HELLO = iota
	CHALLENGE
	CHALLENGE_RESPONSE
	TRANSACTION
	DISCONNECT
	EMIT_TRANSACTION
)

func readUntilFull(amount int, conn net.Conn) ([]byte, error) {
	var msg = make([]byte, amount)
	var idx = 0
	for {
		if n, err := conn.Read(msg[idx:]); err != nil {
			return nil, err
		} else {
			idx += n
			if idx >= amount {
				return msg, nil
			}
		}
	}
}
