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

#define BIFROST_FFI_ABI_VERSION 1u

typedef struct BifrostClient BifrostClient;

/* Status codes returned by bifrost_client_start. */
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
 * Start a client tunnel.
 *
 *   tun_fd            — caller-owned TUN file descriptor. We dup it,
 *                       so the caller is free to close their copy
 *                       on return.
 *   node_config_json  — NUL-terminated JSON describing the norn-rs
 *                       NodeConfig. The `tun_name` field is forced
 *                       to null internally (the host owns the TUN).
 *   exit_pub_key_hex  — NUL-terminated 64-char lowercase hex (ed25519
 *                       pub key of the chosen exit peer).
 *   out_handle        — out-param. On BIFROST_OK, written with a
 *                       freshly-allocated handle pointer that must be
 *                       passed to bifrost_client_stop to release.
 *
 * Returns one of BifrostStatus. On non-zero, *out_handle is left at
 * NULL and bifrost_last_error() returns the reason string.
 */
int32_t bifrost_client_start(
    int32_t            tun_fd,
    const char*        node_config_json,
    const char*        exit_pub_key_hex,
    BifrostClient**    out_handle);

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
