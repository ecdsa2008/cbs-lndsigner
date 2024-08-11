// Copyright (C) 2022-2023 Bottlepay and The Lightning Network Developers

package keyring

import "errors"

var (
	ErrNoSharedKeyReturned = errors.New("wallet returned no shared key")
	ErrBadSharedKey        = errors.New("wallet returned bad shared key")
	ErrNoSignatureReturned = errors.New("wallet returned no signature")
	ErrNoPubkeyReturned    = errors.New("wallet returned no pubkey")
)
