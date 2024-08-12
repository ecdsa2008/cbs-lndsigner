package wallet

import (
	"errors"
	"fmt"
)

var (
	ErrSeedPhraseWrongLength     = errors.New("seed phrase must be 24 words")
	ErrInvalidPassphrase         = errors.New("invalid passphrase")
	ErrSeedPhraseNotBIP39        = errors.New("seed phrase must use BIP39 word list")
	ErrBadCipherSeedVer          = errors.New("cipher seed version not recognized")
	ErrWrongLengthChecksum       = errors.New("wrong length checksum")
	ErrChecksumMismatch          = errors.New("checksum mismatch")
	ErrWrongInternalVersion      = errors.New("wrong internal version")
	ErrNodeAlreadyExists         = errors.New("node already exists")
	ErrNodePubkeyMismatch        = errors.New("node pubkey mismatch")
	ErrInvalidNetwork            = errors.New("invalid network")
	ErrInvalidPeerPubkey         = errors.New("invalid peer pubkey")
	ErrInvalidNodeID             = errors.New("invalid node id")
	ErrNodeNotFound              = errors.New("node not found")
	ErrInvalidSeedFromStorage    = errors.New("invalid seed from storage")
	ErrElementNotHardened        = errors.New("derivation path element not hardened")
	ErrNegativeElement           = errors.New("negative derivation path element")
	ErrWrongLengthDerivationPath = errors.New("derivation path not 5 elements")
	ErrElementOverflow           = errors.New("derivation path element > MaxUint32")
	ErrPubkeyMismatch            = errors.New("pubkey mismatch")
	ErrTooManyTweaks             = errors.New("both single and double tweak specified")

	// ErrIncorrectVersion is returned if a seed bares a mismatched
	// external version to that of the package executing the aezeed scheme.
	ErrIncorrectVersion = fmt.Errorf("wrong seed version")

	// ErrInvalidPass is returned if the user enters an invalid passphrase
	// for a particular enciphered mnemonic.
	ErrInvalidPass = fmt.Errorf("invalid passphrase")

	// ErrIncorrectMnemonic is returned if we detect that the checksum of
	// the specified mnemonic doesn't match. This indicates the user input
	// the wrong mnemonic.
	ErrIncorrectMnemonic = fmt.Errorf("mnemonic phrase checksum doesn't " +
		"match")
)

// ErrUnknownMnemonicWord is returned when attempting to decipher and
// enciphered mnemonic, but a word encountered isn't a member of our word list.
type ErrUnknownMnemonicWord struct {
	// Word is the unknown word in the mnemonic phrase.
	Word string

	// Index is the index (starting from zero) within the slice of strings
	// that makes up the mnemonic that points to the incorrect word.
	Index uint8
}

// Error returns a human-readable string describing the error.
func (e ErrUnknownMnemonicWord) Error() string {
	return fmt.Sprintf("word %v isn't a part of default word list "+
		"(index=%v)", e.Word, e.Index)
}
