use std::{collections::HashSet, fs, time::SystemTime};

pub fn fnmatch(pat: &str, name: &str) -> bool {
    if pat.is_empty() { return false; }
    match pat.find('*') {
        None => pat == name,
        Some(pos) => name.starts_with(&pat[..pos])
            && (pat[pos+1..].is_empty() || name[pos..].ends_with(&pat[pos+1..]))
    }
}

fn rule_prio(pat: &str) -> i32 {
    if pat.is_empty() { return 200; }
    if !pat.contains('*') && !pat.contains('?') { return 1000 + pat.len() as i32; }
    let nw = pat.chars().filter(|c| !matches!(c, '*' | '?' | '[' | ']')).count() as i32;
    if pat.contains('[') { 500 + nw } else if pat.contains('?') { 300 + nw } else { 100 + nw }
}

#[derive(Clone)]
pub struct Rule {
    pub pkg: String,
    pub thread: String,
    pub cpus: String,
    #[allow(dead_code)]
    pub prio: i32,
    /// 包级规则的 cpuset 子目录（load 时预生成）；线程规则为空，匹配时按合并集合创建
    pub cpuset_dir: String,
}

#[derive(Clone)]
pub struct AppConfig {
    pub rules: Vec<Rule>,
    pub pkg_set: HashSet<String>,
    pub wild: Vec<String>,
    pub mtime: SystemTime,
    pub ebpf: bool,
    pub topo: crate::cpuset::CpuTopology,
}

impl AppConfig {
    pub fn load(path: &str, topo: &crate::cpuset::CpuTopology) -> Option<Self> {
        let data = fs::read_to_string(path).ok()?;
        let root = json::parse(&data).ok()?;

        // 彩蛋
        if root["nekonemo"].as_str() == Some("meow") {
            let count = if root.is_object() { root.entries().count() } else { 0 };
            if count <= 1 {
                info!("嗷呜~💗艇长才不是猫娘喵！！！");
                return None;
            }
        }

        let ebpf = root["features"]["ebpf"].as_bool().unwrap_or(false);
        let entries = if root.is_array() { &root } else { &root["rules"] };
        if !entries.is_array() { return None; }

        let mut rules = Vec::new();
        let mut pkg_set = HashSet::new();
        let mut wild = Vec::new();

        for e in entries.members() {
            let pl: Vec<String> = e["packages"].members()
                .filter_map(|v| v.as_str().map(String::from)).collect();
            if pl.is_empty() { continue; }
            let other = e["cpuset"]["other"].as_str().unwrap_or("0");
            let def = pl[0].clone();

            for pk in &pl {
                pkg_set.insert(pk.clone());
                if pk.contains('*') || pk.contains('?') { wild.push(pk.clone()); }
            }

            let other_set = crate::cpuset::from_range(other);
            let other_dir = other_set.to_range_string();
            let other_cpuset_dir = if topo.cpuset_enabled {
                crate::cpuset::create_cpuset_dir(
                    &format!("{}/{}", crate::common::base_cpuset(), other_dir),
                    &other_dir, &topo.mems_str,
                ).then_some(other_dir).unwrap_or_default()
            } else {
                String::new()
            };
            rules.push(Rule { pkg: def.clone(), thread: String::new(), cpus: other.to_string(), prio: 200, cpuset_dir: other_cpuset_dir });

            if e["cpuset"]["comm"].is_object() {
                for (cpus, names) in e["cpuset"]["comm"].entries() {
                    for nv in names.members() {
                        if let Some(name) = nv.as_str() {
                            rules.push(Rule {
                                pkg: def.clone(),
                                thread: name.to_string(),
                                cpus: cpus.to_string(),
                                prio: rule_prio(name),
                                cpuset_dir: String::new(),
                            });
                        }
                    }
                }
            }
        }

        let mt = fs::metadata(path).ok()?.modified().ok()?;
        Some(AppConfig { rules, pkg_set, wild, mtime: mt, ebpf, topo: topo.clone() })
    }

    /// 该包是否存在线程级规则
    pub fn pkg_has_thread_rules(&self, pkg: &str) -> bool {
        self.rules.iter().any(|r| !r.thread.is_empty() && fnmatch(&r.pkg, pkg))
    }
}

pub mod cache {
    use std::{collections::HashSet, fs};
    use super::Rule;

    const FILE: &str = "/sdcard/Android/Aether/threads_cache";

    pub fn merge(set: &mut HashSet<String>, rules: &mut Vec<Rule>) {
        let data = match fs::read_to_string(FILE) { Ok(x) => x, Err(_) => return };
        let root = match json::parse(&data) { Ok(x) => x, Err(_) => return };
        if !root.is_array() { return; }
        let mut seen_pkgs = HashSet::new();
        for entry in root.members() {
            let pl: Vec<String> = entry["packages"].members()
                .filter_map(|v| v.as_str().map(String::from)).collect();
            if pl.is_empty() { continue; }
            // 去重：同名包只保留最后一条（最新）
            if !seen_pkgs.insert(pl[0].clone()) { continue; }
            let other = entry["cpuset"]["other"].as_str().unwrap_or("0");
            for pk in &pl { set.insert(pk.clone()); }
            rules.push(Rule { pkg: pl[0].clone(), thread: String::new(), cpus: other.to_string(), prio: 200, cpuset_dir: String::new() });
            if entry["cpuset"]["comm"].is_object() {
                for (cpus, names) in entry["cpuset"]["comm"].entries() {
                    for nv in names.members() {
                        if let Some(name) = nv.as_str() {
                            rules.push(Rule { pkg: pl[0].clone(), thread: name.to_string(), cpus: cpus.to_string(), prio: super::rule_prio(name), cpuset_dir: String::new() });
                        }
                    }
                }
            }
        }
        info!("已加载 {} 条缓存", seen_pkgs.len());
    }

    /// 用 JSON 库读写 cache，按包名去重覆盖（避免无限膨胀）
    /// 黑名单: 已知无需记忆的系统服务
    pub fn is_blacklisted(pkg: &str) -> bool {
        pkg.ends_with(":widgetProvider") || pkg.ends_with(":searchDataService")
            || pkg.ends_with(":coreService") || pkg.ends_with(":cognitionService")
            || pkg.ends_with(":bert") || pkg.ends_with(":bertAlgo")
            || pkg.ends_with(":privacy") || pkg.ends_with(":kit7")
            || pkg.ends_with(":services") || pkg.ends_with(":daemon")
            || pkg == "android.process.media" || pkg == "android.process.acore"
            || pkg.starts_with("com.qualcomm.") || pkg.starts_with(".qti")
            || pkg.starts_with(".qms") || pkg.starts_with(".cacert")
            || pkg.starts_with(".dataservices")
    }

    pub fn save(pkg: &str, all: &[(i32, String, Vec<(i32, String)>)], big: &str, mid: &str, little: &str) {
        if is_blacklisted(pkg) { return; }
        let mut big_names = Vec::new();
        let mut mid_names = Vec::new();
        let mut lil_names = Vec::new();
        let has_mid = !mid.is_empty();
        for (_, _, th) in all.iter().filter(|(_, n, _)| n == pkg) {
            for (_, comm) in th {
                let load = est_load(comm);
                if load >= 8 { big_names.push(comm.clone()); }
                else if load >= 5 && has_mid { mid_names.push(comm.clone()); }
                else { lil_names.push(comm.clone()); }

            }
        }

        let mut comm_map: std::collections::BTreeMap<&str, Vec<&str>> = std::collections::BTreeMap::new();
        for n in &big_names { comm_map.entry(big).or_default().push(n); }
        for n in &mid_names { comm_map.entry(mid).or_default().push(n); }

        let mut entry = json::JsonValue::new_object();
        entry["friendly"] = json::JsonValue::String(format!("[auto] {}", pkg));
        let mut pkgs = json::JsonValue::new_array();
        let _ = pkgs.push(pkg);
        entry["packages"] = pkgs;
        let mut cs = json::JsonValue::new_object();
        cs["other"] = json::JsonValue::String(little.to_string());
        if !big_names.is_empty() || !mid_names.is_empty() {
            let mut cm = json::JsonValue::new_object();
            for (cpus, ns) in &comm_map {
                let mut arr = json::JsonValue::new_array();
                for n in ns { let _ = arr.push(*n); }
                cm[*cpus] = arr;
            }
            cs["comm"] = cm;
        }
        entry["cpuset"] = cs;

        let _ = fs::create_dir_all("/sdcard/Android/Aether");
        // 用 JSON 库读写，按包名去重
        let old = fs::read_to_string(FILE).unwrap_or_default();
        let arr: json::JsonValue = if old.trim().is_empty() || !old.trim_start().starts_with('[') {
            json::JsonValue::new_array()
        } else {
            json::parse(&old).unwrap_or(json::JsonValue::new_array())
        };
        // 去重：过滤掉同名包名的老条目
        let mut deduped = json::JsonValue::new_array();
        for e in arr.members() {
            let keep = match e["packages"][0].as_str() {
                Some(old_pkg) => old_pkg != pkg,
                None => true,
            };
            if keep {
                let _ = deduped.push(e.clone());
            }
        }
        let _ = deduped.push(entry);
        let _ = fs::write(FILE, json::stringify_pretty(deduped, 2).as_bytes());
    }

    fn est_load(name: &str) -> i32 {
        if name.contains("Render") || name.contains("Gfx") || name.contains("GL") || name.contains("Vulkan") { return 10; }
        if name.contains("Decode") || name.contains("Codec") || name.contains("Video") || name.contains("Audio") { return 8; }
        if name.contains("Main") || name.contains("Unity") || name.contains("Game")
            || name.contains("Native") || name.contains("RHI") || name.contains("TaskGraph") { return 9; }
        if name.contains("Worker") || name.contains("Thread") || name.contains("Job") { return 5; }
        if name.contains("Io") || name.contains("Network") || name.contains("Http") { return 3; }
        if name.contains("Background") || name.contains("Idle") || name.contains("Pool") { return 1; }
        5
    }
}
