// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

const (
	seedLen = 16 // Matches LND usage
)

type Wallet struct {
	Seed          []byte
	NetworkParams *chaincfg.Params
}

func NewWallet(seed []byte, networkParams *chaincfg.Params) *Wallet {
	wallet := &Wallet{
		NetworkParams: networkParams,
		Seed:          seed,
	}
	return wallet
}

type listedAccount struct {
	Name             string `json:"name"`
	AddressType      string `json:"address_type"`
	XPub             string `json:"extended_public_key"`
	DerivationPath   string `json:"derivation_path"`
	ExternalKeyCount int    `json:"external_key_count"`
	InternalKeyCount int    `json:"internal_key_count"`
	WatchOnly        bool   `json:"watch_only"`
}

func (b *Wallet) ListAccounts() (map[string]interface{}, error) {
	rootKey, err := hdkeychain.NewMaster(b.Seed, b.NetworkParams)
	if err != nil {
		return nil, err
	}
	defer rootKey.Zero()

	acctList := make([]*listedAccount, 0, 260)

	listAccount := func(purpose, coin, act uint32, addrType string,
		version []byte) (*listedAccount, error) {
		// Derive purpose. We do these derivations with
		// DeriveNonStandard to match btcwallet's (and thus lnd's)
		// usage as shown here:
		// https://github.com/btcsuite/btcwallet/blob/c314de6995500686c93716037f2279128cc1e9e8/waddrmgr/manager.go#L1459
		purposeKey, err := rootKey.DeriveNonStandard( // nolint:staticcheck
			purpose + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}
		defer purposeKey.Zero()

		// Derive coin.
		coinKey, err := purposeKey.DeriveNonStandard( // nolint:staticcheck
			coin + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}
		defer coinKey.Zero()

		// Derive account.
		actKey, err := coinKey.DeriveNonStandard( // nolint:staticcheck
			act + hdkeychain.HardenedKeyStart,
		)
		if err != nil {
			return nil, err
		}
		defer actKey.Zero()

		// Get account watch-only pubkey.
		xPub, err := actKey.Neuter()
		if err != nil {
			return nil, err
		}

		// Ensure we get the right HDVersion for the account key.
		if version != nil {
			xPub, err = xPub.CloneWithVersion(version)
			if err != nil {
				return nil, err
			}
		}

		strPurpose := fmt.Sprintf("%d", purpose)
		strCoin := fmt.Sprintf("%d", coin)
		strAct := fmt.Sprintf("%d", act)

		listing := &listedAccount{
			Name:        "act:" + strAct,
			AddressType: addrType,
			XPub:        xPub.String(),
			DerivationPath: "m/" + strPurpose + "'/" + strCoin +
				"'/" + strAct + "'",
		}

		if act == 0 {
			listing.Name = "default"
		}

		return listing, nil
	}

	for _, acctInfo := range defaultPurposes {
		listing, err := listAccount(
			acctInfo.purpose,
			0,
			0,
			acctInfo.addrType,
			acctInfo.hdVersion[b.NetworkParams.HDCoinType][:],
		)
		if err != nil {
			log.Println("Failed to derive default account", "err", err)
			return nil, err
		}

		acctList = append(acctList, listing)
	}

	for act := uint32(0); act <= MaxAcctID; act++ {
		listing, err := listAccount(
			Bip0043purpose,
			b.NetworkParams.HDCoinType,
			act,
			"WITNESS_PUBKEY_HASH",
			nil,
		)
		if err != nil {
			log.Println("Failed to derive Lightning account", "err", err)
			return nil, err
		}

		acctList = append(acctList, listing)
	}
	resp, err := json.Marshal(struct {
		Accounts []*listedAccount `json:"accounts"`
	}{
		Accounts: acctList,
	})
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"acctList": string(resp),
	}, nil
}

func (b *Wallet) ECDH(data map[string]interface{}) (map[string]interface{}, error) {

	peerPubHex := ""
	if v1, ok := data["peer"].(string); ok {
		peerPubHex = v1
	}
	var path []int
	if v2, ok := data["path"].([]int); ok {
		path = v2
	}

	pubKeyHex := ""
	if v3, ok := data["pubkey"].(string); ok {
		pubKeyHex = v3
	}

	if len(peerPubHex) != 2*btcec.PubKeyBytesLenCompressed {
		log.Println("Peer pubkey is wrong length",
			"peer", peerPubHex)
		return nil, ErrInvalidPeerPubkey
	}

	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		log.Println("Failed to decode peer pubkey hex",
			"error", err)
		return nil, err
	}

	peerPubKey, err := btcec.ParsePubKey(peerPubBytes)
	if err != nil {
		log.Println("Failed to parse peer pubkey",
			"error", err)
		return nil, err
	}

	var (
		pubJacobian btcec.JacobianPoint
		s           btcec.JacobianPoint
	)
	peerPubKey.AsJacobian(&pubJacobian)

	privKey, err := derivePrivKey(b.Seed, b.NetworkParams, path)
	if err != nil {
		log.Println("Failed to derive privkey", "error", err)
		return nil, err
	}
	defer privKey.Zero()

	err = checkRequiredPubKey(privKey, pubKeyHex)
	if err != nil {
		// We log here as warning because there's no case when we
		// should be using ECDH with a mismatching own key.
		log.Println("Pubkey mismatch", "error", err)
		return nil, err
	}

	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		log.Println("Failed to derive valid ECDSA privkey", "error", err)
		return nil, err
	}
	defer ecPrivKey.Zero()

	btcec.ScalarMultNonConst(&ecPrivKey.Key, &pubJacobian, &s)
	s.ToAffine()
	sPubKey := btcec.NewPublicKey(&s.X, &s.Y)
	h := sha256.Sum256(sPubKey.SerializeCompressed())

	return map[string]interface{}{
		"sharedkey": hex.EncodeToString(h[:]),
	}, nil
}

func (b *Wallet) DerivePubKey(data map[string]interface{}) (map[string]interface{}, error) {
	var path []int
	if v0, ok := data["path"].([]int); ok {
		path = v0
	}

	pubKey, err := derivePubKey(b.Seed, b.NetworkParams, path)
	if err != nil {
		log.Println("Failed to derive pubkey", "error", err)
		return nil, err
	}

	pubKeyBytes, err := extKeyToPubBytes(pubKey)
	if err != nil {
		log.Println("DerivePubKey: Failed to get pubkey bytes", "error", err)
		return nil, err
	}

	return map[string]interface{}{
		"pubkey": hex.EncodeToString(pubKeyBytes),
	}, nil
}

func (b *Wallet) DeriveAndSign(data map[string]interface{}) (map[string]interface{}, error) {

	signMethod := ""
	pubkeyHex := ""
	tapTweakHex := ""
	singleTweakHex := ""
	doubleTweakHex := ""
	digestHex := ""

	var path []int

	v0, ok := data["path"].([]int)
	if ok {
		path = v0
	}

	v1, ok := data["taptweak"].(string)
	if ok {
		tapTweakHex = v1
	}

	v2, ok := data["ln1tweak"].(string)
	if ok {
		singleTweakHex = v2
	}

	v3, ok := data["ln2tweak"].(string)
	if ok {
		doubleTweakHex = v3
	}

	v4, ok := data["pubkey"].(string)
	if ok {
		pubkeyHex = v4
	}

	v5, ok := data["method"].(string)
	if ok {
		signMethod = v5
	}

	v6, ok := data["digest"].(string)
	if ok {
		digestHex = v6
	}

	numTweaks := int(0)

	if len(singleTweakHex) > 0 {
		numTweaks++
	}
	if len(doubleTweakHex) > 0 {
		numTweaks++
	}

	if numTweaks > 1 {
		log.Println("Both single and double tweak specified")
		return nil, ErrTooManyTweaks
	}

	privKey, err := derivePrivKey(b.Seed, b.NetworkParams, path)
	if err != nil {
		log.Println("Failed to derive privkey", "error", err)
		return nil, err
	}
	defer privKey.Zero()

	err = checkRequiredPubKey(privKey, pubkeyHex)
	if err != nil {
		// We log here as info because this is expected when signing
		// a PSBT.
		log.Println("Pubkey mismatch", "error", err)
		return nil, err
	}

	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		log.Println("Failed to derive valid ECDSA privkey", "error", err)
		return nil, err
	}
	defer ecPrivKey.Zero()

	// Taproot tweak.
	var tapTweakBytes []byte

	if len(tapTweakHex) > 0 {
		tapTweakBytes, err = hex.DecodeString(tapTweakHex)
		if err != nil {
			log.Println("Couldn't decode taptweak hex",
				"error", err)
			return nil, err
		}
	}

	if signMethod == "schnorr" {
		ecPrivKey = txscript.TweakTaprootPrivKey(
			*ecPrivKey,
			tapTweakBytes,
		)
	}

	switch {
	// Single commitment tweak as used by SignPsbt.
	case len(singleTweakHex) > 0:
		singleTweakBytes, err := hex.DecodeString(singleTweakHex)
		if err != nil {
			log.Println("Couldn't decode ln1tweak hex",
				"error", err)
			return nil, err
		}

		ecPrivKey = tweakPrivKey(
			ecPrivKey,
			singleTweakBytes,
		)

	// Double revocation tweak as used by SignPsbt.
	case len(doubleTweakHex) > 0:
		doubleTweakBytes, err := hex.DecodeString(doubleTweakHex)
		if err != nil {
			log.Println("Couldn't decode ln2tweak hex",
				"error", err)
			return nil, err
		}

		doubleTweakKey, _ := btcec.PrivKeyFromBytes(doubleTweakBytes)
		ecPrivKey = deriveRevocationPrivKey(ecPrivKey, doubleTweakKey)
	}

	if len(digestHex) != 64 {
		log.Println("Digest is not hex-encoded 32-byte value")
		return nil, errors.New("invalid digest")
	}

	digestBytes, err := hex.DecodeString(digestHex)
	if err != nil {
		log.Println("Failed to decode digest from hex",
			"error", err)
		return nil, err
	}

	var sigBytes []byte

	// TODO(aakselrod): check derivation paths are sane for the type of
	// signature we're requesting.
	switch signMethod {
	case "ecdsa":
		sigBytes = ecdsa.Sign(ecPrivKey, digestBytes).Serialize()
	case "ecdsa-compact":
		sigBytes, _ = ecdsa.SignCompact(ecPrivKey, digestBytes, true)
	case "schnorr":
		sig, err := schnorr.Sign(ecPrivKey, digestBytes)
		if err != nil {
			log.Println("Failed to sign digest using Schnorr", "error", err)
			return nil, err
		}
		sigBytes = sig.Serialize()
	default:
		log.Println("Requested invalid signing method",
			"method", signMethod)
		return nil, errors.New("invalid signing method")
	}

	// We return the pre-tweak pubkey for populating PSBTs and other uses.
	pubKeyBytes, err := extKeyToPubBytes(privKey)
	if err != nil {
		log.Println("DerivePubKey: Failed to get pubkey bytes", "error", err)
		return nil, err
	}

	return map[string]interface{}{
		"signature": hex.EncodeToString(sigBytes),
		"pubkey":    hex.EncodeToString(pubKeyBytes),
	}, nil
}

// GetNodePublicKey return the identity pubkey for the lnd node
func (b *Wallet) GetNodePublicKey() (string, error) {
	nodePubKey, err := derivePubKey(b.Seed, b.NetworkParams, []int{
		Bip0043purpose + hdkeychain.HardenedKeyStart,
		int(b.NetworkParams.HDCoinType + hdkeychain.HardenedKeyStart),
		NodeKeyAcct + hdkeychain.HardenedKeyStart,
		0,
		0,
	})
	if err != nil {
		log.Println("Failed to derive node pubkey from LND seed",
			"error", err)
		return "", err
	}

	pubKeyBytes, err := extKeyToPubBytes(nodePubKey)
	if err != nil {
		log.Println("NewNode: Failed to get pubkey bytes",
			"error", err)
		return "", err
	}

	strPubKey := hex.EncodeToString(pubKeyBytes)

	return strPubKey, nil
}
