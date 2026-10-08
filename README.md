# pwtool

A Rust CLI tool for generating passwords and checking password strength.

## Features

* **Generator:**

  * Custom length (`-l`, `--length`, default: 16).
  * Generate multiple passwords at once (`-n`, `--count`).
  * Character pool filters: `--no-upper`, `--no-lower`, `--no-numbers`, `--no-symbols`.
  * Exclude ambiguous characters (`--no-ambiguous`): `0`, `O`, `1`, `I`, `l`, `|`.
  * Auto-copy to clipboard (`-c`, `--copy`) with an automatic clear countdown (`--clear-after`).
* **Strength Checker:**

  * Analyze passwords through direct arguments or interactive mode (`-i`, `--interactive`).
  * Detect common patterns, dictionary attacks, and repetitions using the `zxcvbn` algorithm.
  * Calculate theoretical entropy versus effective entropy.
  * Estimate cracking time based on an assumption of 10 billion guesses per second using a GPU cluster.
  * Provide warnings and specific recommendations for improving password strength.

## Installation & Build

```bash
cargo build --release
```

The binary will be located at:

```text
target/release/pwtool
```

## Usage

### 1. Generate Passwords

```bash
# Default (16 characters, all character pools enabled)
pwtool generate

# Generate 5 passwords, each 24 characters long
pwtool generate -l 24 -n 5

# Exclude symbols and ambiguous characters (easier to read)
pwtool generate --no-symbols --no-ambiguous

# Copy to clipboard and automatically clear it after 10 seconds
pwtool generate -c --clear-after 10
```

### 2. Check Password Strength

```bash
# Check via command-line argument
pwtool check "Tr0ub4dor&3"

# Interactive mode (password is not displayed on screen or stored in shell history)
pwtool check -i
```

### 3. Testing

```bash
cargo test
```
