# Browser visibility staging

Run `npm test` and `npm run build` with Node 24+. Separate unsigned development ZIPs are emitted into `dist/` for Chrome and Firefox. Build outputs are ignored by Git.

This extension is inactive without the separately installed, protected `com.openems.browser` native messaging broker. That broker is **not implemented or packaged in this stage**. Loading the extension alone does not enable observation. Real-browser, broker, server persistence, managed deployment and signing acceptance remain pending. Do not register a placeholder executable or expose an HTTP collector to bypass pairing.

The popup defaults collection to disabled. Enabling it requires a valid broker handshake and a monitor decision for each committed navigation; allowed and blocked decisions produce no browser observation. Paths require two independent opt-ins. No queries, fragments, credentials, private browsing, content scripts, cookies or history are collected. Pending work is bounded to memory only.

`nativeHostManifest(browser, absoluteExecutable, chromeId)` generates native-host manifest data for a future installer and rejects wildcard Chrome IDs. It does not register a host. The installer must pin the packaged extension's actual ID and validate/protect the broker. See [SPEC.md](SPEC.md) for the protocol and deployment boundaries.
