# Examples

The `silentpaymentscanner` binary implements a silent payments scanner. To run it:
```
cargo run --bin silentpaymentscanner -- /path/to/.bitcoin/regtest
```

The `scripttrace` binary demonstrates the `script_trace` feature, printing a per-opcode execution trace while verifying a transaction. To run it:
```
cargo run --bin scripttrace --features script-trace
```

