/*
 * bifrost-ffi — C ABI for bifrost-vpnd's client data plane.
 *
 * Link the staticlib (`libbifrost_ffi.a`) on iOS and the cdylib
 * (`libbifrost_ffi.so`) on Android. The ABI is pinned by
 * BIFROST_FFI_ABI_VERSION below; assert equality at app launch.
 *
 * See bifrost-ffi/src/lib.rs for full prose on the semantics.
 */

#ifndef BIFROST_FFI_H
#define BIFROST_FFI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BIFROST_FFI_ABI_VERSION 2u

typedef struct BifrostClient BifrostClient;

/* Status codes returned by bifrost_client_connect / _run. */
enum BifrostStatus {
    BIFROST_OK             = 0,
    BIFROST_INVALID_ARG    = 1,
    BIFROST_TUN_FD_ERR     = 2,
    BIFROST_NODE_INIT_ERR  = 3,
    BIFROST_HANDSHAKE_ERR  = 4,
    BIFROST_RUNTIME_ERR    = 5
};

/* ABI sanity check. Must equal BIFROST_FFI_ABI_VERSION. */
uint32_t bifrost_ffi_abi_version(void);

/*
 * Phase 1 — start the node and run the egress handshake.
 *
 * Bring-up is two-phase: a host like Android's VpnService must commit
 * the TUN's IP address before it can give us the fd, yet that address
 * is assigned by the exit during the handshake. So connect first,
 * configure the TUN with the returned lease, then bifrost_client_run.
 *
 *   node_config_json  — NUL-terminated JSON describing the norn-rs
 *                       NodeConfig. The `tun_name` field is forced
 *                       to null internally (the host owns the TUN).
 *   exit_pub_key_hex  — NUL-terminated 64-char lowercase hex (ed25519
 *                       pub key of the chosen exit peer).
 *   out_handle        — out-param. On BIFROST_OK, written with a
 *                       freshly-allocated handle pointer that must be
 *                       passed to bifrost_client_stop to release.
 *   out_lease_v4      — out-param. On BIFROST_OK, the exit-assigned
 *                       IPv4 address in host byte order
 *                       (10.55.0.3 -> 0x0A370003).
 *   out_mtu           — out-param. On BIFROST_OK, the tunnel MTU.
 *
 * Returns one of BifrostStatus. On non-zero, *out_handle is left at
 * NULL and bifrost_last_error() returns the reason string.
 */
int32_t bifrost_client_connect(
    const char*        node_config_json,
    const char*        exit_pub_key_hex,
    BifrostClient**    out_handle,
    uint32_t*          out_lease_v4,
    uint16_t*          out_mtu);

/*
 * Phase 2 — attach the host TUN fd and start the data plane.
 *
 *   handle  — a handle from a successful bifrost_client_connect that
 *             has not yet been run or stopped.
 *   tun_fd  — caller-owned TUN file descriptor. We dup it, so the
 *             caller is free to close their copy on return.
 *
 * Returns one of BifrostStatus. The handle stays owned by the caller
 * either way and must be released with bifrost_client_stop.
 */
int32_t bifrost_client_run(BifrostClient* handle, int32_t tun_fd);

/*
 * Stop a client tunnel. NULL is a no-op. Blocks briefly (~hundreds
 * of ms) waiting for tokio worker threads to wind down; safe to
 * call from a UI thread but consider dispatch_async on iOS / a
 * background HandlerThread on Android.
 */
void bifrost_client_stop(BifrostClient* handle);

/*
 * Borrowed pointer to the last error string (thread-local). Valid
 * only until the next bifrost_* call from the same thread. The
 * library owns the storage — do NOT free it.
 */
const char* bifrost_last_error(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* BIFROST_FFI_H */
