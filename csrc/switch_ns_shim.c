// Tiny C shim that exposes glibc's _res via a versioned-symbol-safe path.
// `extern struct __res_state _res;` references the versioned symbol
// `_res@GLIBC_2.2.5` which the GNU linker resolves automatically; the
// resulting object has a non-versioned reference that Rust can link
// against.
#include <resolv.h>
#include <stdint.h>

extern struct __res_state _res;

void sc_switch_ns_set(uint32_t s_addr) {
    if (_res.nscount > 3) return;
    _res.nscount = 1;
    _res.nsaddr_list[0].sin_family = 2; // AF_INET
    _res.nsaddr_list[0].sin_port = 0;
    _res.nsaddr_list[0].sin_addr.s_addr = s_addr;
}

int sc_res_init(void) {
    return res_init();
}
