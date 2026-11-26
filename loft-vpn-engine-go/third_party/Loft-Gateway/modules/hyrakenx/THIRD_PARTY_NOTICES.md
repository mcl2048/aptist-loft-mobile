# Hyraken X cryptographic implementation

The Rocca-S primitive and AES-NI assembly in this module were copied from
`GhostX-core-main/transport/hyraken` in the same repository. That code follows
`draft-nakano-rocca-s-06` and was checked against the KDDI reference at
https://github.com/yt-nakano/rocca-s. The original source and its notices
remain in `GhostX-core-main/transport/hyraken/THIRD_PARTY_NOTICES.md`.

Rocca-S here uses a 32-byte key, 16-byte nonce, and full 32-byte tag. The
draft's classical claims distinguish 256-bit key recovery from 192-bit
forgery resistance. This local implementation has not had an independent
cryptographic audit.
