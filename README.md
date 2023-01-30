# streamer-go
Golang streaming library for Mevlink's tx streaming service. This library and
the service itself is a pre-release; please contact us via mevlink.com and
we'll be happy to debug any problems with you.

The streamer connects to a TCP socket on the lowest-latency Mevlink node and
authenticates itself via HMAC challenge-response with your API key and ID.
Here's such an example script:

```
package main

import (
	"encoding/hex"
	"log"
	"time"

	mlstreamer "github.com/mevlink/streamer-go"
	"golang.org/x/crypto/sha3"
)

func main() {
  var str = mlstreamer.NewStreamer("262c956a76c7009ab38cdba6302ec105", "14361648f02f8eab7ef5b48f1df58e8a")
  str.OnTransaction(func(txb []byte, noticed, propagated time.Time) {
    //Getting the transaction hash and printing the relevant times
    var hasher = sha3.NewLegacyKeccak256()
    hasher.Write(txb)
    var tx_hash = hasher.Sum(nil)

    log.Println("Got tx '" + hex.EncodeToString(tx_hash) + "'! Was noticed on ", noticed, "and sent on", propagated)
  })
  log.Fatal(str.Stream())
}
```

This library gives you a callback that three things:
- The full encoded RLP transaction bytes.
- The time at which the Mevlink node first learned of the transaction's
  existence (for example, via a NEW\_POOLED\_TRANSACTION\_HASHES request)
- The time at which the Mevlink node sent the transaction to you over the TCP
  stream.

The binary streaming API is deliberately simple; if you are interested in
learning how it works, feel free to read the comments. The ordering of the
emitted fields, timing information, and MAC is such that you can choose to
consider/respond to transactions before you have timing information or have
verified the authentication signature.

The stream gives no guarantee of transactions being valid or will be
successfully processed on-chain by BSC fullnodes; it simply provides
transaction that have been seen via P2P node connections. Stay sharp, and
verify what you need to.

On our immediate roadmap:
- Introduce a UDP socket to remove TCP performance/reordering issues.
- Add configuration options for receiving blocks, optional encryption, timing information.
