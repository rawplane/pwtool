# pwtool

CLI tool generator dan pemeriksa kekuatan password di Rust.

## Fitur

- **Generator:**
  - Panjang kustom (`-l`, `--length`, default: 16).
  - Banyak output sekaligus (`-n`, `--count`).
  - Opsi filter: `--no-upper`, `--no-lower`, `--no-numbers`, `--no-symbols`.
  - Hindari karakter ambigu (`--no-ambiguous`: `0`, `O`, `1`, `I`, `l`, `|`).
  - Auto-copy ke clipboard (`-c`, `--copy`) + auto-clear countdown (`--clear-after`).
- **Strength Checker:**
  - Analisis via argumen langsung atau mode interaktif (`-i`, `--interactive`).
  - Deteksi pola umum, dictionary attack, pengulangan via algoritma `zxcvbn`.
  - Perhitungan entropi teoretis vs entropi efektif.
  - Estimasi waktu retas (asumsi 10 miliar tebakan/detik cluster GPU).
  - Peringatan dan saran perbaikan spesifik.

## Instalasi & Build

```bash
cargo build --release
```

Binary tersimpan di `target/release/pwtool`.

## Penggunaan

### 1. Generate Password

```bash
# Default (16 karakter, semua pool aktif)
pwtool generate

# Panjang 24 karakter, 5 baris
pwtool generate -l 24 -n 5

# Tanpa simbol dan karakter ambigu (mudah dibaca)
pwtool generate --no-symbols --no-ambiguous

# Salin ke clipboard dan hapus otomatis setelah 10 detik
pwtool generate -c --clear-after 10
```

### 2. Cek Kekuatan Password

```bash
# Cek via argumen
pwtool check "Tr0ub4dor&3"

# Cek interaktif (password tidak tampil di layar/history shell)
pwtool check -i
```

### 3. Testing

```bash
cargo test
```
