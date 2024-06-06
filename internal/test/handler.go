package test

import (
	"fmt"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

// HandlerLoop blocks until the handler has finished. The result of the execution is given by Handler.Result().
func HandlerLoop(id party.ID, h protocol.Handler, network *Network) {
	fmt.Printf("party %s, handler loop started\n", id)
	for {
		select {

		// outgoing messages
		case msg, ok := <-h.Listen():
			if !ok {
				fmt.Printf("party %s, channel closed\n", id)
				<-network.Done(id)
				// the channel was closed, indicating that the protocol is done executing.
				return
			}
			fmt.Printf("party %s, sending %v\n", id, msg)
			go network.Send(msg)

		// incoming messages
		case msg := <-network.Next(id):
			fmt.Printf("party %s, received %v\n", id, msg)
			h.Accept(msg)
		}
	}
}
