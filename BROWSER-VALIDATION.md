# Browser validation — 2026-10-22

> Historical evidence for the installed build on that date. Later CA/Edge acceptances and the incomplete final Chrome/Firefox trial are recorded in [HANDOFF](HANDOFF.md) and [ACCEPTANCE](ACCEPTANCE.md). Do not apply the environment limitations below to a newer build without checking those records. The [web-filter manual](docs/web-filter-compatibility.md) describes current policy semantics.

Validation used the user's authenticated Chrome session and the installed agent. No policies, certificates, service configuration, DNS settings or installed executables were changed.

## Observed results

| Check | Result | Evidence |
|---|---|---|
| Endpoint connection | Passed | Console reports `RSM000100` online and Applied. |
| Policy acknowledgement | Passed | Desired and applied profile are Default v2, digest `e4953b7634ea3446099c7e513794b2c52c97b8adeb760347f0bad6af600672ea`; no application error. |
| HTTP blocked site | Passed | `http://example.com/` displays the RSM branded block page. |
| HTTPS blocked site | Not accepted | `https://example.com/` returns `ERR_CERT_AUTHORITY_INVALID`; the warning was not bypassed. |
| Allowed site | Passed | `https://www.iana.org/` loads its normal content. |

The active profile blocks `example.com` and `neverssl.com`. Hosts entries for `example.com` and `www.example.com` resolve to `127.0.0.1`.

## Installed environment limitations

- The installed `openems-agent` service is Running with automatic startup.
- The installed executable differs from the new local release build. This session did not deploy the HTTPS implementation.
- No certificate matching openems was found in `LocalMachine\\Root`.
- The agent owns the loopback HTTP listener on port 80. Port 443 has Docker/WSL listeners; the observed browser certificate error cannot establish that the new agent HTTPS listener works.
- The protected agent configuration could not be read by the current process. No attempt was made to change its permissions.
- `WindowsSandbox.exe` exists, but Sandbox feature activation has not been confirmed. The read-only DISM query requires elevation.

Screenshots are local, ignored artifacts in `.venv/browser-validation/http-block.png` and `.venv/browser-validation/endpoint-applied.png`.

## Next acceptance steps

Use disposable Windows, as required by `https-blockpage.md` and `HANDOFF.md`. Verify an available loopback port 443 before enabling HTTPS. Install the new build and its own machine CA explicitly, then verify blocked HTTP/HTTPS and allowed HTTPS in Chrome, Edge and Firefox without bypassing certificate warnings. Change the policy and verify revocation. Validate restart/recovery, exact CA removal, uninstall and rollback while retaining unrelated trust roots. MSI acceptance also requires building the changed installer.

These steps remain pending. Browser checks of the installed version do not replace them. No CI, push or MSI publication was performed.
