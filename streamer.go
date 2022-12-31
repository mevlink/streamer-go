package mlstreamer

import (
	"bytes"
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

type Streamer struct{
  m sync.Mutex

  KeyId string
  KeySecret string

  subs []func (txb []byte, noticed, propagated time.Time)
}

//Creates a streamer with a userId and keyId, which you can retrieve from the
//mevlink website.
func NewStreamer(keyId, keySecret string) *Streamer {
  var ret Streamer
  ret.KeyId = keyId
  ret.KeySecret = keySecret
  return &ret
}

//Provides a callback giving RLP-encoded transaction bytes when they are
//received. See the Stream() function code for a detailed description of the
//noticed and propagated times.
func (s *Streamer) OnTransaction(f func (txb []byte, noticed, propagated time.Time)) {
  s.m.Lock()
  s.subs = append(s.subs, f)
  s.m.Unlock()
}

func (s *Streamer) Stream() error {
  for {
    if err := s._stream(); err != nil {
      log.Println("mevlink streaming error: " + err.Error() + "; reconnecting in one second...")
      time.Sleep(time.Second);
    } else {
      return nil;
    }
  }
}

//Begins the streaming process and starts making callbacks to functions
//provided in OnTransaction. Automatically attempts to reconnect. Errors if the
//connection handshake fails despite a backoff.
func (s *Streamer) _stream() error {
  for {
    conn, mac, err := s.connect()
    if err != nil {
      return errors.Wrap(err, "error connecting outright");
    }

    //Now we are authenticated and the server should start sending TRANSACTION messages.
    for {
      msg_id, err := readUntilFull(1, conn)
      if err != nil {
        return errors.Wrap(err, "error reading msg id byte")
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
          return errors.Wrap(err, "error reading tx ln header")
        }
        {
          if tx[0] < 0xc0 {
            return errors.New("unsupported tx error")
          } else if tx[0] < 0xf8 {
            txb_remaining, err := readUntilFull(int(tx[0]-0xc0), conn)
            if err != nil {
              return errors.Wrap(err, "error reading tx body");
            }
            tx = append(tx, txb_remaining...)
          } else {
            var ln_of_ln = tx[0] - 0xf7
            txb_ln, err := readUntilFull(int(ln_of_ln), conn)
            if err != nil {
              return errors.Wrap(err, "error reading tx body");
            }
            tx = append(tx, txb_ln...)
            var i_b = append(make([]byte, 8-ln_of_ln), txb_ln...)
            ln := binary.BigEndian.Uint64(i_b)
            txb, err := readUntilFull(int(ln), conn)
            if err != nil {
              return errors.Wrap(err, "error reading tx body");
            }
            tx = append(tx, txb...)
          }
        }

        //Now that you have the transaction, you can either respond to it
        //immediately or wait for timing information and MAC indicating it hasn't
        //been tampered with and is recent enough to act upon.

        //Next is the "propagated" timestamp. This is a unix microsecond
        //timestamp of when the mevlink relay received and sent us the
        //transaction.
        propagated_b, err := readUntilFull(8, conn)
        if err != nil {
          return errors.Wrap(err, "error reading propagation bytes");
        }
        propagated := time.UnixMicro(int64(binary.BigEndian.Uint64(propagated_b)))

        //Finally, we have the "noticed" timestamp. This gives the earliest time
        //mevlink heard of the transaction's existence from other peers on BSC.
        //Note that this may not be the earliest time *any* mevlink relay has
        //heard about the transaction at time of sending.
        noticed_b, err := readUntilFull(8, conn)
        if err != nil {
          return errors.Wrap(err, "error reading noticed bytes");
        }
        noticed := time.UnixMicro(int64(binary.BigEndian.Uint64(noticed_b)))

        //Finally, the mac
        given_mac, err := readUntilFull(32, conn)
        if err != nil {
          return errors.Wrap(err, "error reading mac");
        }
        mac.Reset()
        mac.Write(msg_id)
        mac.Write(tx)
        mac.Write(propagated_b)
        mac.Write(noticed_b)
        if bytes.Compare(given_mac, mac.Sum(nil)) != 0 {
          return errors.New("mac was incorrect")
        } else {
          s.m.Lock()
          for _, f := range s.subs {
            f(tx, noticed, propagated)
          }
          s.m.Unlock()
        }
      default:
        log.Fatal("No other message ids at present")
      }
    }
  }
}

func (s *Streamer) connect() (net.Conn, hash.Hash, error) {
  var streaming_ip_loc string
  if provided_host := os.Getenv("MEVLINK_HOST"); provided_host == "" {
    streaming_ip_loc = "https://mevlink.com/api/get_node_ips"
  } else {
    streaming_ip_loc = provided_host + "/api/get_node_ips"
  }

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
    conn, err := net.Dial("tcp", ip + ":25568")
    if err != nil {
      return nil,nil, errors.Wrap(err, "could not connect to server at " + ip)
    }
    delay := time.Now().Sub(startedAt)
    if delay < bestLatency {
      bestLatency = delay
      bestConn = conn
    } else if err := conn.Close(); err != nil {
      return nil, nil, errors.Wrap(err, "error closing rejected streaming connection at " + ip)
    }
  }
  if bestConn == nil {
    return nil, nil, errors.New("no servers active or couldn't get acceptable latency; check your connection")
  }

	//Send hello message with protocol version and user id
	hello := make([]byte, 1+1+16)
	hello[0] = HELLO                                                     //Message ID
	hello[1] = 0x00                                                      //Only valid protocol version for now
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
    return nil, nil, errors.Wrap(err, "error reading challenge bytes")
	}
	if challenge_msg_b[0] != CHALLENGE {
    bestConn.Close()
    return nil, nil, errors.Wrap(err, "error reading challenge bytes")
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
