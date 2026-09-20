// scratch/p4_server.rs — verbatim replication of pizauth's cache_path()
// (pizauth/src/main.rs:74-105) + sock_path() leaf (src/server/mod.rs:65-69)
// + the plain UnixListener::bind from src/server/mod.rs:444 (no chmod on the
// socket itself), so the control socket's real permission posture at HEAD can
// be measured offline under an adversarial umask.
//
// Mode "pizauth"  : exact pizauth behaviour (create-if-missing + chmod 0700
//                   on BOTH dir components, fatal on chmod failure).
// Mode "umaskonly": the counterfactual from the claim — dirs left to umask,
//                   no 0700 enforcement — used only to prove the connector
//                   oracle is sensitive (it must succeed here).
use std::{
    env, fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
    process,
};

const PIZAUTH_CACHE_LEAF: &str = "pizauth";
const PIZAUTH_CACHE_SOCK_LEAF: &str = "pizauth.sock";

fn fatal(msg: &str) -> ! {
    eprintln!("{msg:}");
    process::exit(1);
}

fn username() -> Option<String> {
    env::var("USER").ok().filter(|s| !s.is_empty())
}

fn cache_path(enforce: bool) -> PathBuf {
    let mut p = PathBuf::new();
    match env::var_os("XDG_RUNTIME_DIR") {
        Some(s) => p.push(s),
        None => {
            p.push(env::var_os("TMPDIR").unwrap_or_else(|| "/tmp".into()));
            p.push(format!(
                "runtime-{}",
                username().unwrap_or_else(|| "unknown-user".to_owned())
            ));
        }
    }

    let md = |p: &PathBuf| {
        if !p.exists() {
            fs::create_dir(p).unwrap_or_else(|e| fatal(&format!("Can't create cache dir: {e}")));
        }
        if enforce {
            fs::set_permissions(p, PermissionsExt::from_mode(0o700)).unwrap_or_else(|_| {
                fatal(&format!(
                    "Can't set permissions for {} to 0700 (octal)",
                    p.to_str()
                        .unwrap_or("<path cannot be represented as UTF-8>")
                ))
            });
        }
    };

    md(&p);
    p.push(PIZAUTH_CACHE_LEAF);
    md(&p);

    p
}

fn main() {
    let mode = env::args().nth(1).unwrap_or_else(|| "pizauth".into());
    let enforce = mode != "umaskonly";
    let cache = cache_path(enforce);
    let mut sock = cache.clone();
    sock.push(PIZAUTH_CACHE_SOCK_LEAF);
    let _ = fs::remove_file(&sock);
    let listener =
        UnixListener::bind(&sock).unwrap_or_else(|e| fatal(&format!("bind failed: {e}")));
    println!("mode={mode}");
    println!("socket_path={}", sock.display());
    println!(
        "runtime_dir_mode={:o}",
        fs::metadata(cache.parent().unwrap()).unwrap().permissions().mode() & 0o7777
    );
    println!(
        "cache_dir_mode={:o}",
        fs::metadata(&cache).unwrap().permissions().mode() & 0o7777
    );
    println!(
        "socket_mode={:o}",
        fs::metadata(&sock).unwrap().permissions().mode() & 0o7777
    );
    // Block in accept() exactly like pizauth's serial loop (mod.rs:455-460);
    // one accepted connection prints a marker and lets the process exit.
    match listener.accept() {
        Ok((_stream, _)) => {
            println!("accepted_connection=yes");
        }
        Err(e) => {
            println!("accepted_connection=no ({e})");
        }
    }
}
