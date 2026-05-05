# nostr-vpn-app-core

Native shells use this crate as the shared app contract.

It currently owns:

- the UI snapshot structs that mirror the legacy app model
- the typed native state used by the macOS SwiftUI shell
- the complete typed action set corresponding to current app behavior
- platform capability projection for desktop, Android, and iPhone
- a UniFFI `FfiApp` object with `state`, `refresh`, and `dispatch`
