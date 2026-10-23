/* Minimal input fixture for a local clang -target bpf smoke test. */
#define SEC(name) __attribute__((section(name), used))
#define XDP_PASS 2

SEC("xdp")
int xdp_allow_all(void *context)
{
    (void)context;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
