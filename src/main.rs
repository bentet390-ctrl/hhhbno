use sha2::{Sha256, Digest};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Instant, Duration};
use std::collections::VecDeque;
use std::sync::Mutex;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

const API_BASE: &str = "https://api.rpow2.com";

// ── Structs API ──────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Clone)]
struct Challenge {
    challenge_id: String,
    nonce_prefix: String,
    difficulty_bits: u32,
}

#[derive(Serialize, Debug)]
struct MintRequest {
    challenge_id: String,
    solution_nonce: String,
}

#[derive(Deserialize, Debug, Default)]
struct MintResponse {
    reward: Option<serde_json::Value>,
    amount: Option<serde_json::Value>,
    points: Option<serde_json::Value>,
    balance: Option<serde_json::Value>,
    message: Option<String>,
    #[serde(flatten)]
    extra: std::collections::HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Debug)]
struct Me {
    email: Option<String>,
    balance: Option<serde_json::Value>,
    #[serde(flatten)]
    extra: std::collections::HashMap<String, serde_json::Value>,
}

// ── Stats tracking ───────────────────────────────────────────────────────────

struct Stats {
    total_hashes: AtomicU64,
    total_minted: AtomicU64,
    start_time: Instant,
}

impl Stats {
    fn new() -> Arc<Self> {
        Arc::new(Stats {
            total_hashes: AtomicU64::new(0),
            total_minted: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }

    fn hashrate(&self) -> f64 {
        let h = self.total_hashes.load(Ordering::Relaxed);
        let s = self.start_time.elapsed().as_secs_f64();
        if s > 0.0 { h as f64 / s } else { 0.0 }
    }

    fn add_hashes(&self, n: u64) {
        self.total_hashes.fetch_add(n, Ordering::Relaxed);
    }
}

// ── Difficulty log ───────────────────────────────────────────────────────────

struct DifficultyLog {
    entries: Mutex<VecDeque<(u32, u64, Duration)>>,
}

impl DifficultyLog {
    fn new() -> Arc<Self> {
        Arc::new(DifficultyLog {
            entries: Mutex::new(VecDeque::new()),
        })
    }

    fn record(&self, difficulty: u32, balance_delta: u64, time: Duration) {
        let mut e = self.entries.lock().unwrap();
        e.push_back((difficulty, balance_delta, time));
        if e.len() > 50 { e.pop_front(); }
    }

    fn print_analysis(&self) {
        let e = self.entries.lock().unwrap();
        if e.len() < 2 { return; }
        println!("\n=== ANALISIS difficulty vs reward ===");
        let mut map: std::collections::HashMap<u32, Vec<(u64, f64)>> = Default::default();
        for (diff, reward, time) in e.iter() {
            map.entry(*diff).or_default().push((*reward, time.as_secs_f64()));
        }
        let mut keys: Vec<u32> = map.keys().cloned().collect();
        keys.sort();
        for k in keys {
            let v = &map[&k];
            let avg_r = v.iter().map(|(r,_)| *r as f64).sum::<f64>() / v.len() as f64;
            let avg_t = v.iter().map(|(_,t)| t).sum::<f64>() / v.len() as f64;
            let eff = if avg_t > 0.0 { avg_r / avg_t } else { 0.0 };
            println!("  diff={:2} | avg_reward={:.1} | avg_time={:.1}s | reward/sec={:.4} | n={}", k, avg_r, avg_t, eff, v.len());
        }
        println!("=====================================\n");
    }
}

// ── Hashing core ─────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("Hex length ganjil: {}", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("Hex invalid di pos {}: {}", i, e)))
        .collect()
}

fn trailing_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for i in (0..hash.len()).rev() {
        let byte = hash[i];
        if byte == 0 { count += 8; }
        else { count += byte.trailing_zeros(); return count; }
    }
    count
}

fn mine_range_tracked(
    prefix: &[u8], difficulty: u32, start: u64, step: u64,
    found: &AtomicBool, stats: &Stats,
) -> Option<u64> {
    let mut buf = vec![0u8; prefix.len() + 8];
    buf[..prefix.len()].copy_from_slice(prefix);
    let mut nonce = start;
    let mut local_count = 0u64;

    loop {
        if found.load(Ordering::Relaxed) {
            stats.add_hashes(local_count);
            return None;
        }
        buf[prefix.len()..].copy_from_slice(&nonce.to_le_bytes());
        let hash = Sha256::digest(&buf);
        if trailing_zero_bits(&hash) >= difficulty {
            found.store(true, Ordering::Relaxed);
            stats.add_hashes(local_count + 1);
            return Some(nonce);
        }
        nonce = nonce.wrapping_add(step);
        local_count += 1;
        if local_count % 100_000 == 0 {
            stats.add_hashes(100_000);
            local_count = 0;
        }
    }
}

// ── API Probe ────────────────────────────────────────────────────────────────

async fn probe_api(client: &Client, cookie: &str) {
    println!("\n[PROBE] Reverse engineering API endpoints...\n");

    for path in &["/me", "/leaderboard", "/stats", "/config", "/history",
                  "/rewards", "/balance", "/info", "/difficulty", "/top"] {
        let url = format!("{}{}", API_BASE, path);
        if let Ok(r) = client.get(&url).header("cookie", cookie).send().await {
            let status = r.status();
            if status.as_u16() != 404 && status.as_u16() != 405 {
                let body = r.text().await.unwrap_or_default();
                println!("  [OK] GET {} -> {} | {}", path, status,
                    if body.len() > 120 { format!("{}...", &body[..120]) } else { body });
            }
        }
    }

    println!("\n[PROBE] Test concurrent challenge grab...");
    let mut ids = vec![];
    for i in 0..3 {
        if let Ok(r) = client.post(format!("{}/challenge", API_BASE)).header("cookie", cookie).send().await {
            let body = r.text().await.unwrap_or_default();
            println!("  Challenge #{}: {}", i+1, if body.len() > 150 { &body[..150] } else { &body });
            if let Ok(c) = serde_json::from_str::<Challenge>(&body) { ids.push(c.challenge_id); }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("  Hasil: {} challenges diperoleh -> {}", ids.len(),
        if ids.len() > 1 { "BISA PARALLEL!" } else { "Hanya 1 per request" });

    println!("\n[PROBE] Full /me response:");
    if let Ok(r) = client.get(format!("{}/me", API_BASE)).header("cookie", cookie).send().await {
        println!("  {}", r.text().await.unwrap_or_default());
    }
    println!("\n[PROBE] Selesai. Mulai mining...\n");
}

// ── Solver ───────────────────────────────────────────────────────────────────

async fn solve_challenge(challenge: &Challenge, threads: usize, stats: Arc<Stats>) -> Option<u64> {
    let prefix = match hex_to_bytes(&challenge.nonce_prefix) {
        Ok(p) => p,
        Err(e) => { eprintln!("[!] hex error: {}", e); return None; }
    };
    let difficulty = challenge.difficulty_bits;
    let found = Arc::new(AtomicBool::new(false));
    let solution = Arc::new(AtomicU64::new(u64::MAX));

    let handles: Vec<_> = (0..threads).map(|i| {
        let prefix = prefix.clone();
        let found = Arc::clone(&found);
        let solution = Arc::clone(&solution);
        let stats = Arc::clone(&stats);
        thread::spawn(move || {
            if let Some(nonce) = mine_range_tracked(&prefix, difficulty, i as u64, threads as u64, &found, &stats) {
                solution.compare_exchange(u64::MAX, nonce, Ordering::SeqCst, Ordering::Relaxed).ok();
            }
        })
    }).collect();

    for h in handles { h.join().ok(); }

    let n = solution.load(Ordering::Relaxed);
    if n == u64::MAX { None } else { Some(n) }
}

// ── Pipeline miner per akun ───────────────────────────────────────────────────

async fn mine_account(cookie: String, threads: usize, idx: usize, stats: Arc<Stats>, diff_log: Arc<DifficultyLog>, do_probe: bool) {
    let client = Client::builder().timeout(Duration::from_secs(30)).build().unwrap();

    let (label, mut bal_prev) = match client.get(format!("{}/me", API_BASE)).header("cookie", &cookie).send().await {
        Ok(r) => if let Ok(me) = r.json::<Me>().await {
            let email = me.email.unwrap_or_else(|| format!("account-{}", idx+1));
            let bal = me.balance.as_ref().and_then(|v| v.as_u64()).unwrap_or(0);
            if !me.extra.is_empty() { println!("[*] [{}] /me extra: {:?}", email, me.extra); }
            (email, bal)
        } else { (format!("account-{}", idx+1), 0) },
        Err(_) => (format!("account-{}", idx+1), 0),
    };

    println!("[*] [{}] Start | threads={} | balance={}", label, threads, bal_prev);

    if do_probe { probe_api(&client, &cookie).await; }

    let mut total_minted = 0u64;
    let mut consecutive_errors = 0u32;

    let (tx, mut rx) = mpsc::channel::<Challenge>(2);

    match client.post(format!("{}/challenge", API_BASE)).header("cookie", &cookie).send().await {
        Ok(r) => match r.json::<Challenge>().await {
            Ok(c) => { tx.send(c).await.ok(); }
            Err(e) => { eprintln!("[!] [{}] Parse challenge: {}", label, e); return; }
        },
        Err(e) => { eprintln!("[!] [{}] Fetch challenge: {}", label, e); return; }
    };

    while let Some(challenge) = rx.recv().await {
        println!("[*] [{}] challenge={} | diff={} | {:.0} H/s",
            label, &challenge.challenge_id[..8.min(challenge.challenge_id.len())],
            challenge.difficulty_bits, stats.hashrate());

        {
            let c2 = client.clone(); let ck2 = cookie.clone(); let tx2 = tx.clone(); let lbl2 = label.clone();
            tokio::spawn(async move {
                for attempt in 0..10 {
                    if attempt > 0 { tokio::time::sleep(Duration::from_secs(5)).await; }
                    match c2.post(format!("{}/challenge", API_BASE)).header("cookie", &ck2).send().await {
                        Ok(r) => if let Ok(c) = r.json::<Challenge>().await { tx2.send(c).await.ok(); break; }
                        Err(e) => eprintln!("[!] [{}] pre-fetch err: {}", lbl2, e),
                    }
                }
            });
        }

        let t0 = Instant::now();
        let Some(nonce) = solve_challenge(&challenge, threads, Arc::clone(&stats)).await else {
            consecutive_errors += 1;
            if consecutive_errors > 5 { break; }
            continue;
        };
        let solve_time = t0.elapsed();
        println!("[+] [{}] Nonce={} in {:.2}s", label, nonce, solve_time.as_secs_f64());

        let mint_req = MintRequest { challenge_id: challenge.challenge_id.clone(), solution_nonce: nonce.to_string() };
        match client.post(format!("{}/mint", API_BASE)).header("cookie", &cookie).json(&mint_req).send().await {
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                if status.is_success() {
                    total_minted += 1;
                    consecutive_errors = 0;

                    let reward_str = if let Ok(mr) = serde_json::from_str::<MintResponse>(&body) {
                        let mut parts = vec![];
                        if let Some(v) = &mr.reward  { parts.push(format!("reward={}", v)); }
                        if let Some(v) = &mr.amount  { parts.push(format!("amount={}", v)); }
                        if let Some(v) = &mr.points  { parts.push(format!("points={}", v)); }
                        if let Some(v) = &mr.balance { parts.push(format!("balance={}", v)); }
                        if !mr.extra.is_empty() { parts.push(format!("extra={:?}", mr.extra)); }
                        if parts.is_empty() { format!("raw={}", &body[..body.len().min(100)]) } else { parts.join(" | ") }
                    } else { format!("raw={}", &body[..body.len().min(100)]) };

                    let bal_now = client.get(format!("{}/me", API_BASE)).header("cookie", &cookie)
                        .send().await.ok()
                        .and_then(|r| futures::executor::block_on(r.json::<Me>()).ok())
                        .and_then(|m| m.balance.and_then(|v| v.as_u64()))
                        .unwrap_or(bal_prev);

                    let delta = bal_now.saturating_sub(bal_prev);
                    diff_log.record(challenge.difficulty_bits, delta, solve_time);
                    bal_prev = bal_now;

                    println!("[+] [{}] Mint #{} | diff={} | +{} balance | total={} | {}",
                        label, total_minted, challenge.difficulty_bits, delta, bal_now, reward_str);

                    if total_minted % 5 == 0 {
                        diff_log.print_analysis();
                        let mins = stats.start_time.elapsed().as_secs_f64() / 60.0;
                        println!("[*] [{}] Rate: {:.2} mint/min | {:.0} H/s | total minted: {}",
                            label, total_minted as f64 / mins, stats.hashrate(), total_minted);
                    }
                } else {
                    eprintln!("[!] [{}] Mint GAGAL ({}) | diff={} | nonce={} | {}",
                        label, status, challenge.difficulty_bits, nonce, &body[..body.len().min(200)]);
                    consecutive_errors += 1;
                }
            }
            Err(e) => { eprintln!("[!] [{}] Mint error: {}", label, e); consecutive_errors += 1; }
        }

        if consecutive_errors > 5 { eprintln!("[!] [{}] Terlalu banyak error, stop", label); break; }
    }
}

// ── Load accounts dari env var ───────────────────────────────────────────────
// Format RPOW_ACCOUNTS di Railway:
//   - Satu cookie  : isi langsung cookie stringnya
//   - Banyak cookie: pisahkan dengan |||
//   Contoh: cookie1_value|||cookie2_value|||cookie3_value

fn load_accounts_from_env() -> Vec<String> {
    let raw = std::env::var("RPOW_ACCOUNTS").unwrap_or_else(|_| {
        eprintln!("[!] Env var RPOW_ACCOUNTS tidak ditemukan!");
        eprintln!("[!] Set di Railway: Settings > Variables > RPOW_ACCOUNTS");
        eprintln!("[!] Format: satu cookie, atau pisahkan banyak cookie dengan |||");
        std::process::exit(1);
    });

    // Support separator ||| (untuk Railway) atau newline (untuk lokal)
    let accounts: Vec<String> = if raw.contains("|||") {
        raw.split("|||")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    } else {
        raw.lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && !s.starts_with('#'))
            .collect()
    };

    if accounts.is_empty() {
        eprintln!("[!] RPOW_ACCOUNTS kosong atau format salah.");
        std::process::exit(1);
    }

    accounts
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let total_threads: usize = std::env::var("RPOW_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(num_cpus::get);

    let do_probe = std::env::var("RPOW_PROBE")
        .map(|v| v == "1")
        .unwrap_or(false);

    let accounts = load_accounts_from_env();
    let num_accounts = accounts.len();
    let base = total_threads / num_accounts;
    let remainder = total_threads % num_accounts;

    println!("=== rpow2 Optimized Miner v2.0 ===");
    println!("[*] Accounts : {}", num_accounts);
    println!("[*] Threads  : {} (dibagi rata)", total_threads);
    println!("[*] Probe    : {}", if do_probe { "ON" } else { "OFF (set RPOW_PROBE=1 untuk aktifkan)" });
    println!("[*] Fitur    : pipeline mining, race condition fix, stats tracking\n");

    let stats = Stats::new();
    let diff_log = DifficultyLog::new();
    let mut tasks = Vec::new();

    for (i, cookie) in accounts.into_iter().enumerate() {
        let t = (base + if i < remainder { 1 } else { 0 }).max(1);
        tasks.push(tokio::spawn(mine_account(
            cookie, t, i,
            Arc::clone(&stats),
            Arc::clone(&diff_log),
            do_probe && i == 0,
        )));
    }

    for task in tasks { let _ = task.await; }
}
