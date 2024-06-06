package frost

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, adaptorSecret curve.Secp256k1Scalar, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c0 := r.(*Config)

	t.Logf("config after DKG - Party %s: %s", id, configStr(c0))

	h, err = protocol.NewMultiHandler(Refresh(c0, ids), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)
	require.True(t, c0.PublicKey.Equal(c.PublicKey))
	t.Logf("config after refresh - Party %s: %s", id, configStr(c0))

	h, err = protocol.NewMultiHandler(KeygenTaproot(id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	c0Taproot := r.(*TaprootConfig)

	h, err = protocol.NewMultiHandler(RefreshTaproot(c0Taproot, ids), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &TaprootConfig{}, r)

	cTaproot := r.(*TaprootConfig)
	require.True(t, bytes.Equal(c0Taproot.PublicKey, cTaproot.PublicKey))

	h, err = protocol.NewMultiHandler(Sign(c, ids, message), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))

	h, err = protocol.NewMultiHandler(SignTaproot(cTaproot, ids, message), nil)
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)

	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.Signature{}, signResult)
	taprootSignature := signResult.(taproot.Signature)
	assert.True(t, cTaproot.PublicKey.Verify(taprootSignature, message))

	adaptorPoint := adaptorSecret.ActOnBase().(*curve.Secp256k1Point)
	h, err = protocol.NewMultiHandler(SignTaprootAdaptor(cTaproot, ids, *adaptorPoint, message), nil)
	require.NoError(t, err)

	test.HandlerLoop(c.ID, h, n)
	signResult, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, taproot.AdaptorSignature{}, signResult)
	adaptorSignature := signResult.(taproot.AdaptorSignature)
	assert.True(t, cTaproot.PublicKey.VerifyAdaptor(adaptorSignature, *adaptorPoint, message))
	finalSignature, err := adaptorSignature.Complete(adaptorSecret)
	require.NoError(t, err)
	assert.True(t, cTaproot.PublicKey.Verify(finalSignature, message))
}

func doDkgOnly(t *testing.T, id party.ID, ids []party.ID, threshold int, n *test.Network) Config {
	h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	return *r.(*Config)
}

func doSigningOnly(t *testing.T, c Config, ids []party.ID, message []byte, n *test.Network, wg *sync.WaitGroup) {
	defer wg.Done()
	h, err := protocol.NewMultiHandler(Sign(&c, ids, message), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, Signature{}, signResult)
	signature := signResult.(Signature)
	assert.True(t, signature.Verify(c.PublicKey, message))
}

func TestFrost(t *testing.T) {
	N := 5
	T := N - 1
	message := []byte("hello")

	group := curve.Secp256k1{}
	adaptorSecret := sample.Scalar(rand.Reader, group).(*curve.Secp256k1Scalar)

	partyIDs := test.PartyIDs(N)
	fmt.Println(partyIDs)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go do(t, id, partyIDs, T, message, *adaptorSecret, n, &wg)
	}
	wg.Wait()
}

func TestFrostRealisticSign(t *testing.T) {
	// this should be a 3 of 5 scheme (max two parties corrupted during keygen)
	N := 5
	T := 2
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	dkgNetwork := test.NewNetwork(partyIDs)

	t.Logf("REALISTIC SIGN TEST: DKG")
	fmt.Printf("DKG parties: %s", partyIDs)
	configs := make(map[party.ID]Config)
	var wg sync.WaitGroup
	wg.Add(N)
	for _, id := range partyIDs {
		go func() {
			configs[id] = doDkgOnly(t, id, partyIDs, T, dkgNetwork)
			wg.Done()
		}()
	}
	wg.Wait()

	signingIDs := test.PartyIDs(3) // three signers. Should meet quorum.
	signNetwork := test.NewNetwork(signingIDs)
	t.Logf("REALISTIC SIGN TEST: Signing")
	fmt.Printf("signing parties: %s", signingIDs)
	var signWg sync.WaitGroup
	signWg.Add(len(signingIDs))
	for _, id := range signingIDs {
		c := configs[id]
		go doSigningOnly(t, c, signingIDs, message, signNetwork, &signWg)
	}
	signWg.Wait()
}

func configStr(c *Config) string {
	pubkeyBinary, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	privateShareBinary, err := c.PrivateShare.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`ID: %s
PublicKey: %x
ChainKey: %x
PrivateShare %x
VerificationShares %v
`, c.ID, pubkeyBinary, c.ChainKey, privateShareBinary, c.VerificationShares)
}
