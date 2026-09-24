use std::io::{self, Write};
use std::thread::sleep;
use std::time::Duration;

use clap::{Parser, Subcommand};
use rand::seq::{IndexedRandom, SliceRandom};

// ponytail: single file CLI, upgrade to multi-module when exceeding 350 lines

#[derive(Parser)]
#[command(name = "pwtool", about = "CLI password generator & strength checker", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate password acak aman
    Generate {
        /// Panjang password
        #[arg(short, long, default_value_t = 16)]
        length: usize,

        /// Jumlah password yang dihasilkan
        #[arg(short = 'n', long, default_value_t = 1)]
        count: usize,

        /// Tanpa huruf besar (A-Z)
        #[arg(long)]
        no_upper: bool,

        /// Tanpa huruf kecil (a-z)
        #[arg(long)]
        no_lower: bool,

        /// Tanpa angka (0-9)
        #[arg(long)]
        no_numbers: bool,

        /// Tanpa simbol (!@#$%^&*...)
        #[arg(long)]
        no_symbols: bool,

        /// Tanpa karakter ambigu (0, O, 1, I, l, |)
        #[arg(long)]
        no_ambiguous: bool,

        /// Salin password ke clipboard
        #[arg(short, long)]
        copy: bool,

        /// Hapus clipboard otomatis setelah N detik (hanya jika --copy aktif)
        #[arg(long, default_value_t = 10)]
        clear_after: u64,
    },

    /// Cek kekuatan dan entropi password
    Check {
        /// Password yang ingin dicek
        password: Option<String>,

        /// Input password secara tersembunyi
        #[arg(short, long)]
        interactive: bool,
    },
}

const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const NUMBERS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";
const AMBIGUOUS: &[u8] = b"0O1Il|";

fn is_ambiguous(b: u8) -> bool {
    AMBIGUOUS.contains(&b)
}

fn generate_one(
    len: usize,
    upper: bool,
    lower: bool,
    num: bool,
    sym: bool,
    no_ambig: bool,
) -> Result<String, String> {
    if len == 0 {
        return Err("Panjang password minimal 1 karakter".into());
    }

    let filter = |chars: &[u8]| -> Vec<u8> {
        chars
            .iter()
            .copied()
            .filter(|&c| !no_ambig || !is_ambiguous(c))
            .collect()
    };

    let mut pools: Vec<Vec<u8>> = Vec::new();
    if upper {
        pools.push(filter(UPPER));
    }
    if lower {
        pools.push(filter(LOWER));
    }
    if num {
        pools.push(filter(NUMBERS));
    }
    if sym {
        pools.push(filter(SYMBOLS));
    }

    pools.retain(|p| !p.is_empty());
    if pools.is_empty() {
        return Err("Semua karakter dimatikan atau terfilter oleh --no-ambiguous".into());
    }

    let mut rng = rand::rng();
    let mut password_bytes: Vec<u8> = Vec::with_capacity(len);

    // Ambil minimal 1 karakter dari tiap pool yang aktif
    for pool in &pools {
        if password_bytes.len() < len {
            if let Some(&c) = pool.choose(&mut rng) {
                password_bytes.push(c);
            }
        }
    }

    // Isi sisa panjang dari pool gabungan
    let all_chars: Vec<u8> = pools.into_iter().flatten().collect();
    while password_bytes.len() < len {
        if let Some(&c) = all_chars.choose(&mut rng) {
            password_bytes.push(c);
        }
    }

    // Acak urutan karakter
    password_bytes.shuffle(&mut rng);

    String::from_utf8(password_bytes).map_err(|e| e.to_string())
}

fn format_duration(seconds: f64) -> String {
    if seconds < 0.001 {
        "seketika (< 1 ms)".into()
    } else if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1} detik", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} menit", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} jam", seconds / 3600.0)
    } else if seconds < 31_536_000.0 {
        format!("{:.1} hari", seconds / 86400.0)
    } else if seconds < 31_536_000_000.0 {
        format!("{:.1} tahun", seconds / 31_536_000.0)
    } else {
        "berabad-abad (> 1000 tahun)".into()
    }
}

fn check_strength(pass: &str) {
    if pass.is_empty() {
        eprintln!("\x1b[31mPassword kosong!\x1b[0m");
        return;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_sym = false;
    for c in pass.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else {
            has_sym = true;
        }
    }

    let mut pool_size: usize = 0;
    if has_lower {
        pool_size += 26;
    }
    if has_upper {
        pool_size += 26;
    }
    if has_digit {
        pool_size += 10;
    }
    if has_sym {
        pool_size += 33;
    }

    let raw_entropy = if pool_size > 0 {
        (pass.len() as f64) * (pool_size as f64).log2()
    } else {
        0.0
    };

    let res = zxcvbn::zxcvbn(pass, &[]);
    let score = res.score();
    let guesses = res.guesses();
    let effective_entropy = if guesses > 1 {
        (guesses as f64).log2()
    } else {
        0.0
    };

    // 1e10 = 10 miliar tebakan/detik (kecepatan offline cluster GPU/hashcat)
    let crack_seconds = (guesses as f64) / 10_000_000_000.0;

    let (score_text, score_color) = match score {
        zxcvbn::Score::Zero => ("0/4 [Sangat Lemah]", "\x1b[1;31m"),
        zxcvbn::Score::One => ("1/4 [Lemah]", "\x1b[31m"),
        zxcvbn::Score::Two => ("2/4 [Cukup]", "\x1b[33m"),
        zxcvbn::Score::Three => ("3/4 [Kuat]", "\x1b[32m"),
        zxcvbn::Score::Four => ("4/4 [Sangat Kuat]", "\x1b[1;32m"),
        _ => ("Unknown", "\x1b[0m"),
    };

    println!("\n=== Analisis Kekuatan Password ===");
    println!("Panjang          : {} karakter", pass.len());
    println!("Charset Pool     : {} kemungkinan karakter", pool_size);
    println!("Entropi Teoretis : {:.1} bit", raw_entropy);
    println!("Entropi Efektif  : {:.1} bit", effective_entropy);
    println!("Skor Keamanan    : {}{}\x1b[0m", score_color, score_text);
    println!(
        "Estimasi Crack   : {} (kecepatan 10 miliar tebakan/detik)",
        format_duration(crack_seconds)
    );

    if let Some(fb) = res.feedback() {
        if let Some(w) = fb.warning() {
            println!("\x1b[33mPeringatan       : {}\x1b[0m", w);
        }
        let suggestions = fb.suggestions();
        if !suggestions.is_empty() {
            println!("Saran Perbaikan  :");
            for s in suggestions {
                println!("  - {}", s);
            }
        }
    }
    println!();
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            length,
            count,
            no_upper,
            no_lower,
            no_numbers,
            no_symbols,
            no_ambiguous,
            copy,
            clear_after,
        } => {
            let mut first_pass: Option<String> = None;

            for i in 0..count {
                match generate_one(
                    length,
                    !no_upper,
                    !no_lower,
                    !no_numbers,
                    !no_symbols,
                    no_ambiguous,
                ) {
                    Ok(pw) => {
                        println!("{}", pw);
                        if i == 0 {
                            first_pass = Some(pw);
                        }
                    }
                    Err(e) => {
                        eprintln!("\x1b[31mError: {}\x1b[0m", e);
                        std::process::exit(1);
                    }
                }
            }

            if copy {
                if let Some(pw) = first_pass {
                    match arboard::Clipboard::new() {
                        Ok(mut cb) => {
                            if let Err(e) = cb.set_text(&pw) {
                                eprintln!("\x1b[31mGagal menyalin ke clipboard: {}\x1b[0m", e);
                            } else {
                                println!(
                                    "\x1b[32mPassword disalin ke clipboard! Menunggu {} detik sebelum dibersihkan...\x1b[0m",
                                    clear_after
                                );
                                io::stdout().flush().ok();
                                sleep(Duration::from_secs(clear_after));
                                let _ = cb.clear();
                                println!("\x1b[33mClipboard dibersihkan.\x1b[0m");
                            }
                        }
                        Err(e) => {
                            eprintln!("\x1b[31mClipboard error: {}\x1b[0m", e);
                        }
                    }
                }
            }
        }

        Commands::Check {
            password,
            interactive,
        } => {
            let pass = if interactive {
                match rpassword::prompt_password("Masukkan password untuk dicek: ") {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("\x1b[31mGagal membaca input: {}\x1b[0m", e);
                        std::process::exit(1);
                    }
                }
            } else if let Some(p) = password {
                p
            } else {
                eprintln!("\x1b[31mError: Berikan argumen password atau gunakan flag -i/--interactive\x1b[0m");
                std::process::exit(1);
            };

            check_strength(&pass);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_length_and_charset() {
        let pw = generate_one(20, true, true, true, true, false).unwrap();
        assert_eq!(pw.len(), 20);

        let no_sym = generate_one(16, true, true, true, false, false).unwrap();
        assert_eq!(no_sym.len(), 16);
        assert!(!no_sym.bytes().any(|b| SYMBOLS.contains(&b)));

        let no_ambig = generate_one(30, true, true, true, true, true).unwrap();
        assert!(!no_ambig.bytes().any(is_ambiguous));
    }

    #[test]
    fn test_all_pools_disabled_error() {
        let res = generate_one(10, false, false, false, false, false);
        assert!(res.is_err());
    }

    #[test]
    fn test_duration_format() {
        assert_eq!(format_duration(0.0001), "seketika (< 1 ms)");
        assert_eq!(format_duration(120.0), "2.0 menit");
    }
}
