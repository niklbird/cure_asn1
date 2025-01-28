use std::str::from_utf8;

use crate::{
    labeling::parse_oid,
    rpki_utils::{byt_to_in, parse_ip},
    tree_parser::Tree,
};
use base64::{prelude::BASE64_STANDARD, Engine};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    hash::{Hash, Hasher},
};

use std::error::Error;
pub struct RpkiObject {
    pub content: Tree,
    pub typ: String,
}

impl RpkiObject {
    pub fn new(content: Tree, typ: String) -> RpkiObject {
        RpkiObject { content, typ }
    }

    pub fn get_roa_vrps(&self) -> Option<Vec<String>> {
        let asn = self.get_roa_asn()?;
        let ips = self.get_roa_ips_string();
        let mut vrps = vec![];
        for ip in ips {
            vrps.push(format!("{},{}", asn, ip));
        }
        Some(vrps)
    }

    pub fn get_roa_asn(&self) -> Option<u64> {
        let raw = self.content.get_raw_by_label("AS-ID");

        if raw.is_none() {
            return None;
        }

        let raw = raw.unwrap();

        let mut result: u64 = 0;
        for (_, &byte) in raw.iter().enumerate() {
            result = (result << 8) | (byte as u64);
        }
        Some(result)
    }

    pub fn get_roa_ips_string(&self) -> Vec<String> {
        let mut ips = vec![];
        let n = self.content.get_node_by_label("IpAddresses");
        if n.is_none() {
            return ips;
        }

        let n = n.unwrap();
        for child in &n.children {
            let child_node = self.content.get_node(*child).unwrap();
            let family = byt_to_in(self.content.tokens[&child_node.children[0]].data.clone());
            for full_ip in &self.content.tokens[&child_node.children[1]].children {
                let nod = self.content.get_node(*full_ip).unwrap();
                if nod.children.len() < 1 {
                    println!(
                        "No children in IP node {:?}",
                        BASE64_STANDARD.encode(self.content.encode())
                    );
                    continue;
                }
                let ip_nod = self.content.get_node(nod.children[0]).unwrap();
                let ip_raw = ip_nod.data.clone();
                let padding = ip_raw[0];

                let ip = parse_ip(
                    &ip_raw[1..].to_vec(),
                    family.try_into().unwrap(),
                    padding as usize,
                );
                let ml;
                if nod.children.len() == 2 {
                    let child = self.content.get_node(nod.children[1]).unwrap();
                    if child.data.len() == 1 {
                        ml = child.data[0];
                    } else {
                        ml = byt_to_in(child.data.clone()).try_into().unwrap_or(0);
                    };
                } else {
                    ml = ip.split("/").collect::<Vec<&str>>()[1]
                        .parse::<u8>()
                        .unwrap();
                }
                if ml == 0 {
                    println!(
                        "ML is 0 {}, child len {:?}",
                        ip,
                        self.content.get_node(nod.children[1]).unwrap()
                    );
                }
                let final_ip = ip + "," + &ml.to_string();
                ips.push(final_ip);
            }
        }
        ips
    }

    pub fn get_mft_number(&self) -> Option<u64> {
        let data = self.content.get_raw_by_label("manifestNumber")?;

        let number = byt_to_in(data);
        return Some(number);
    }

    pub fn get_cert_ski(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("subjectKeyIdentifier")?;
        Some(hex::encode(data))
    }

    pub fn get_cert_is_root(&self) -> bool {
        return self
            .content
            .get_node_by_label("authorityKeyIdentifierExtID")
            .is_none();
    }

    pub fn get_cert_notification_uri(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("rpkiNotifyURI")?;

        Some(from_utf8(&data).unwrap_or_default().to_string())
    }

    pub fn get_cert_rsync_repo_uri(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("caRepositoryURI")?;

        Some(from_utf8(&data).unwrap_or_default().to_string())
    }

    pub fn get_cert_signed_uri(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("signedObjectURI")?;

        Some(from_utf8(&data).unwrap_or_default().to_string())
    }

    pub fn get_cert_aki(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("authorityKeyIdentifier")?;
        Some(hex::encode(data))
    }

    pub fn get_cert_issuername(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("issuerName")?;

        Some(from_utf8(&data).unwrap_or_default().to_string())
    }

    pub fn get_cert_subjectname(&self) -> Option<String> {
        let data = self.content.get_raw_by_label("subjectName")?;

        Some(from_utf8(&data).unwrap().to_string())
    }

    pub fn get_signature_oid(&self) -> String {
        let data = self.content.get_raw_by_label("signerSignatureAlgorithmOid");
        if data.is_none() {
            return "Unknown".to_string();
        }
        parse_oid(&data.unwrap())
    }
}

pub fn parse_rpki_object(data: &Vec<u8>, typ: &ObjectType) -> Option<RpkiObject> {
    let r = crate::asn1_parser::parse_asn1_object_slim(data);
    if r.is_err() {
        println!("Error during parsing {:?}", r);
        return None;
    }

    let root = r.unwrap();

    let tree = Tree::generate_tree(root, typ.to_string());

    Some(RpkiObject {
        content: tree,
        typ: typ.to_string(),
    })
}

#[derive(Debug, Clone, PartialEq)]
pub enum ObjectType {
    ROA,
    MFT,
    CERTCA,
    CERTEE,
    CERTROOT,
    CRL,
    ASA,
    GBR,
    UNKNOWN,
    NOTIFICATION,
    SNAPSHOT,
    DELTA,
}

impl ObjectType {
    // String to ObjectType, corresponds to using the file extension.
    pub fn from_string(s: &str) -> ObjectType {
        match s {
            "roa" => ObjectType::ROA,
            "mft" => ObjectType::MFT,
            "cer" => ObjectType::CERTCA,
            "crl" => ObjectType::CRL,
            "asa" => ObjectType::ASA,
            "gbr" => ObjectType::GBR,
            "notification" => ObjectType::NOTIFICATION,
            "snapshot" => ObjectType::SNAPSHOT,
            "delta" => ObjectType::DELTA,
            _ => ObjectType::UNKNOWN,
        }
    }

    pub fn is_valid_string(s: &str) -> bool {
        match s {
            "roa" => true,
            "mft" => true,
            "cer" => true,
            "crl" => true,
            "asa" => true,
            "gbr" => true,
            "notification" => true,
            "snapshot" => true,
            "delta" => true,
            _ => false,
        }
    }
}

impl ToString for ObjectType {
    fn to_string(&self) -> String {
        match self {
            ObjectType::ROA => "roa".to_string(),
            ObjectType::MFT => "mft".to_string(),
            ObjectType::CERTCA => "cer".to_string(),
            ObjectType::CERTEE => "cer".to_string(),
            ObjectType::CERTROOT => "cer".to_string(),
            ObjectType::CRL => "crl".to_string(),
            ObjectType::ASA => "asa".to_string(),
            ObjectType::GBR => "gbr".to_string(),
            ObjectType::UNKNOWN => "unknown".to_string(),
            ObjectType::NOTIFICATION => "notification".to_string(),
            ObjectType::SNAPSHOT => "snapshot".to_string(),
            ObjectType::DELTA => "delta".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct TAL {
    pub http_uri: String,
    pub rsync_uri: String,
    pub certificate: Vec<u8>,
}

impl TAL {
    pub fn from_content(tal_content: &str) -> Result<TAL, Box<dyn Error>> {
        // Define regex patterns for URIs
        let http_regex = Regex::new(r"^https?://[^\s]+")?;
        let rsync_regex = Regex::new(r"^rsync://[^\s]+")?;

        // Initialize variables for the URIs and certificate
        let mut http_uri = String::new();
        let mut rsync_uri = String::new();
        let mut certificate_base64 = String::new();

        // Process each line to capture the HTTP, RSYNC URIs and Base64 certificate
        for line in tal_content.lines() {
            if http_regex.is_match(line) {
                http_uri = line.to_string();
            } else if rsync_regex.is_match(line) {
                rsync_uri = line.to_string();
            } else {
                certificate_base64.push_str(line);
            }
        }

        // Decode the certificate
        let certificate = BASE64_STANDARD.decode(certificate_base64)?;

        // Return the parsed TAL struct
        Ok(TAL {
            http_uri,
            rsync_uri,
            certificate,
        })
    }
}

pub fn ipstring_to_bytes(ip: &str, family: &IPType) -> Vec<u8> {
    let mut parts = vec![];

    let ip_no_pre = ip.split("/").collect::<Vec<&str>>()[0];
    if family == &IPType::V4 {
        for el in ip_no_pre.split(".") {
            let ell = el.parse::<u8>();
            if ell.is_err() {
                println!("Couldnt parse {:?}", el);
                return vec![];
            }
            let el = ell.unwrap();
            parts.push(el);
        }
        return parts;
    } else {
        for el in ip_no_pre.split(":") {
            if el.is_empty() {
                parts.push(0);
                parts.push(0);
            } else {
                let ell = u16::from_str_radix(el, 16);
                if ell.is_err() {
                    println!("Couldnt parse {:?}", el);
                    return vec![];
                }
                let el = ell.unwrap();
                parts.push((el >> 8) as u8);
                parts.push((el & 0xFF) as u8);
            }
        }
        return parts;
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Metadata {
    counts: u32,
    generated: u64,
    valid: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRoa {
    pub prefix: String,
    pub max_length: u8,
    pub asn: String,
    pub ta: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct VrpsData {
    metadata: Metadata,
    roas: Vec<JsonRoa>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum IPType {
    V4,
    V6,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct IPEntry {
    pub ip_s: String,
    pub ip: Vec<u8>,
    pub prefix: u8,
    pub max_len: u8,
    pub typ: IPType,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub ip: IPEntry,
    pub asn: u32,
}

impl Entry {
    pub fn entries_to_vrp_format(entries: &Vec<Entry>) -> String {
        let mut res = String::new();
        for entry in entries {
            res.push_str(&format!(
                "{}/{} => AS{}\n",
                entry.ip.ip_s, entry.ip.prefix, entry.asn
            ));
        }
        res
    }

    pub fn from_roa_str(raw: &str) -> Option<Entry> {
        if !raw.contains("=>") {
            return None;
        }

        let s = raw.split("=>").collect::<Vec<&str>>();

        let asn_raw = s[1];
        let mut asn_raw = asn_raw.trim();
        if asn_raw.starts_with("AS") {
            asn_raw = &asn_raw[2..];
        }

        let asn = asn_raw.parse::<u32>();
        if asn.is_err() {
            return None;
        }

        let asn = asn.unwrap();

        let ip_raw = s[0];
        let ip_raw = ip_raw.trim();
        let ip = ip_raw.split("/").nth(0).unwrap().to_string();

        let prefix = ip_raw.split("/").nth(1).unwrap().parse::<u8>().unwrap();

        let ml = prefix;
        // let new_raw = format!("{},{},{}", s[1], s[0], prefix);

        let family = if ip.contains(":") {
            IPType::V6
        } else {
            IPType::V4
        };

        let vrps_ip = IPEntry {
            ip_s: ip.clone(),
            ip: ipstring_to_bytes(&ip, &family),
            prefix,
            max_len: ml,
            typ: family,
        };

        Some(Entry { ip: vrps_ip, asn })
    }

    pub fn from_str(raw: &str) -> Option<Entry> {
        let parts: Vec<&str> = raw.split(",").collect();
        let mut asn_raw = parts[0];
        if asn_raw.starts_with("AS") {
            asn_raw = &asn_raw[2..];
        }
        let asn = asn_raw.parse::<u32>();
        if asn.is_err() {
            return None;
        }
        let asn = asn.unwrap();
        let ip = parts[1].to_string();
        let prefix = parts[1].split("/").nth(1).unwrap().parse::<u8>().unwrap();

        let ml = parts[2].parse::<u8>().unwrap_or(prefix);
        // let new_raw = format!("{},{},{}", parts[0], parts[1], parts[2]);

        let family = if ip.contains(":") {
            IPType::V6
        } else {
            IPType::V4
        };

        let vrps_ip = IPEntry {
            ip_s: ip.clone(),
            ip: ipstring_to_bytes(&ip, &family),
            prefix,
            max_len: ml,
            typ: family,
        };

        Some(Entry { ip: vrps_ip, asn })
    }

    pub fn from_json(roa: &JsonRoa) -> Option<Entry> {
        let mut asn_raw = roa.asn.as_str();
        if asn_raw.starts_with("AS") {
            asn_raw = &asn_raw[2..];
        }
        let asn = asn_raw.parse::<u32>();
        if asn.is_err() {
            return None;
        }
        let asn = asn.unwrap();
        let ip = roa.prefix.clone();
        let prefix = roa.prefix.split('/').nth(1).unwrap().parse::<u8>().unwrap();

        // let new_raw = format!("{},{},{}", roa.asn, roa.prefix, roa.max_length);

        let family = if ip.contains(":") {
            IPType::V6
        } else {
            IPType::V4
        };

        let vrps_ip = IPEntry {
            ip_s: ip.clone(),
            ip: ipstring_to_bytes(&ip, &family),
            prefix,
            max_len: roa.max_length,
            typ: family,
        };

        Some(Entry { ip: vrps_ip, asn })
    }
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip && self.ip.prefix == other.ip.prefix && self.asn == other.asn
    }
}

// Since Eq is a marker trait, we don't need to implement any methods for it,
// we just declare that Entry implements Eq.
impl Eq for Entry {}

// Implement Hash for Entry
impl Hash for Entry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.ip_s.hash(state);
        self.ip.prefix.hash(state);
        self.asn.hash(state);
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DiffEntry {
    pub entry: Entry,
    pub missing_from: Vec<String>,
}

impl PartialEq for DiffEntry {
    fn eq(&self, other: &Self) -> bool {
        let entries = self.entry == other.entry;
        // Check if missing from is identical
        let missing: bool = self
            .missing_from
            .iter()
            .zip(other.missing_from.iter())
            .all(|(a, b)| a == b);
        entries && missing
    }
}

impl Eq for DiffEntry {}

// Implement Hash for Entry
impl Hash for DiffEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.entry.hash(state);
        self.missing_from.hash(state);
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VRPS {
    pub content: Vec<Entry>,
    pub rp_name: String,
}

impl VRPS {
    pub fn from_entries(entries: HashSet<Entry>, rp_name: &str) -> VRPS {
        VRPS {
            content: entries.into_iter().collect(),
            rp_name: rp_name.to_string(),
        }
    }

    pub fn from_content(content: &str, rp_name: &str) -> VRPS {
        if content.contains("{") {
            VRPS::from_json(&content, &rp_name)
        } else {
            VRPS::from_csv(&content, &rp_name)
        }
    }

    pub fn from_file(file_uri: &str, rp_name: &str) -> VRPS {
        let content = std::fs::read_to_string(file_uri).unwrap();
        VRPS::from_content(&content, &rp_name)
    }

    pub fn from_csv(csv: &str, rp_name: &str) -> VRPS {
        let lines = csv.split("\n");
        let mut content = vec![];
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let entry = Entry::from_str(line);
            if entry.is_none() {
                continue;
            }
            let entry = entry.unwrap();
            content.push(entry);
        }
        VRPS {
            content,
            rp_name: rp_name.to_string(),
        }
    }

    pub fn from_json(json_str: &str, rp_name: &str) -> VRPS {
        let data: VrpsData = serde_json::from_str(json_str).unwrap();
        let mut entries = Vec::new();
        for roa in data.roas.iter() {
            if let Some(entry) = Entry::from_json(roa) {
                entries.push(entry);
            }
        }
        VRPS {
            content: entries,
            rp_name: rp_name.to_string(),
        }
    }

    pub fn from_objects(objects: HashMap<String, Vec<u8>>, base_uri: &str) -> VRPS {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(6)
            .build()
            .unwrap();
        let roa_ips: Vec<_> = pool.install(|| {
            objects
                .par_iter()
                .map(|(uri, data)| {
                    let ext = uri.split('.').last().unwrap();
                    let optype = ObjectType::from_string(ext);
                    if optype != ObjectType::ROA {
                        return None;
                    }
                    let tree = parse_rpki_object(&data, &optype);
                    if tree.is_none() {
                        println!("Failed to parse {:?}", uri);
                        return None;
                    }

                    let tree = tree.unwrap();
                    let ips = tree.get_roa_ips_string();
                    let asn = tree.get_roa_asn().unwrap_or(0);
                    return Some((uri.clone(), asn, ips));
                })
                .collect()
        });

        // store_roa_map(&roa_ips, base_uri);

        let mut vrps = HashSet::new();
        for roa in &roa_ips {
            if roa.is_none() {
                continue;
            }
            let roa = roa.clone().unwrap();
            let uri = roa.0.clone();
            let asn = roa.1.clone();
            let ips = roa.2.clone();

            for ip in ips {
                let ip = ip.to_string();
                let ip = ip.split(",").collect::<Vec<_>>()[0];
                // let ip = s[0..s.len() - 1].join("/");
                let s = format!("{} => {}", ip, asn);
                let entry = Entry::from_roa_str(&s);
                if entry.is_none() {
                    println!("Failed to parse {:?}", uri);
                    continue;
                }
                let entry = entry.unwrap();
                vrps.insert(entry);
            }
        }

        let vrps = VRPS::from_entries(vrps, "crawler");
        let s = serde_json::to_string(&vrps).unwrap();
        let path = format!("{}/vrps.dump", base_uri);
        fs::write(path, s).unwrap();
        return vrps;
    }

    pub fn differences(&self, other: &VRPS) -> (Vec<Entry>, Vec<Entry>) {
        let mut not_in_a: Vec<Entry> = vec![];
        let mut not_in_b: Vec<Entry> = vec![];

        let self_content_set: HashSet<&Entry> = self.content.iter().collect();
        let other_content_set: HashSet<&Entry> = other.content.iter().collect();

        for entry in &self.content {
            if !other_content_set.contains(&entry) {
                not_in_b.push(entry.clone());
            }
        }

        for entry in &other.content {
            if !self_content_set.contains(&entry) {
                not_in_a.push(entry.clone());
            }
        }

        (not_in_a, not_in_b)
    }

    pub fn differences_many(&self, others: Vec<VRPS>) -> Vec<DiffEntry> {
        let mut not_in: Vec<DiffEntry> = vec![];
        let mut all_set: HashSet<&Entry> = HashSet::new();

        // Collect entries from self.content into all_set
        for entry in &self.content {
            all_set.insert(entry);
        }

        // Collect entries from others into all_set
        for other in &others {
            for entry in &other.content {
                all_set.insert(entry);
            }
        }

        // Create a HashSet for fast lookup of entries in self.content and others
        let self_content_set: HashSet<&Entry> = self.content.iter().collect();
        let others_content_sets: Vec<HashSet<&Entry>> = others
            .iter()
            .map(|other| other.content.iter().collect())
            .collect();

        for entr in all_set {
            let mut missing_from = vec![];
            if !self_content_set.contains(entr) {
                missing_from.push(self.rp_name.clone());
            }

            for (i, other_set) in others_content_sets.iter().enumerate() {
                if !other_set.contains(entr) {
                    missing_from.push(others[i].rp_name.clone());
                }
            }

            if missing_from.len() > 0 {
                let dif_entry = DiffEntry {
                    entry: entr.clone(),
                    missing_from,
                };
                not_in.push(dif_entry);
            }
        }

        not_in
    }

    pub fn contains_entry_asn(&self, asn: u32) -> bool {
        for con in &self.content {
            if con.asn == asn {
                return true;
            }
        }
        return false;
    }

    // pub fn load_for_rps(rp_names: &Vec<String>) -> Vec<VRPS> {
    //     let configs = config_parser::parse_configs();
    //     let mut all_vrps = vec![];

    //     // let mut parsed_logs = vec![];
    //     for conf in configs {
    //         if !rp_names.contains(&conf.0) {
    //             continue;
    //         }

    //         let file = conf.1.vrps_file.1;
    //         let content = std::fs::read_to_string(&file);
    //         if content.is_err() {
    //             continue;
    //         }

    //         let content = content.unwrap();
    //         let vrp;
    //         if conf.0 == "octorpki" {
    //             vrp = VRPS::from_json(&content, &conf.0);
    //         } else {
    //             vrp = VRPS::from_csv(&content, &conf.0);
    //         }

    //         all_vrps.push(vrp);
    //     }
    //     all_vrps
    // }
}
