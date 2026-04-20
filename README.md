# Process Sandbox (seccomp-bpf)

Lightweight user-space sandbox for running workloads with syscall restrictions.

## Build

```bash
make
```

## Run

```bash
./sandbox-run policies/restrictive.json ./test
```

## GUI

```bash
make gui
```

Open: http://127.0.0.1:8080
