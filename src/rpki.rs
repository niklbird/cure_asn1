use std::str::from_utf8;

use crate::{
    rpki_utils::{byt_to_in, parse_ip},
    tree_parser::Tree,
};
use base64::decode;
use regex::Regex;

use std::error::Error;
pub struct RpkiObject {
    pub content: Tree,
    pub typ: String,
}

impl RpkiObject {
    pub fn new(content: Tree, typ: String) -> RpkiObject {
        RpkiObject { content, typ }
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
                    println!("No children in IP node {:?}", base64::encode(self.content.encode()));
                    continue;
                }
                let ip_nod = self.content.get_node(nod.children[0]).unwrap();
                let ip_raw = ip_nod.data.clone();
                let padding = ip_raw[0];

                let ip = parse_ip(&ip_raw[1..].to_vec(), family.try_into().unwrap(), padding as usize);
                let ml;
                if nod.children.len() == 2 {
                    let child = self.content.get_node(nod.children[1]).unwrap();
                    if child.data.len() == 1 {
                        ml = child.data[0];
                    } else {
                        ml = byt_to_in(child.data.clone()).try_into().unwrap_or(0);
                    };
                } else {
                    ml = ip.split("/").collect::<Vec<&str>>()[1].parse::<u8>().unwrap();
                }
                if ml == 0 {
                    println!("ML is 0 {}, child len {:?}", ip, self.content.get_node(nod.children[1]).unwrap());
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
        return self.content.get_node_by_label("authorityKeyIdentifierExtID").is_none();
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
        let certificate = decode(certificate_base64)?;

        // Return the parsed TAL struct
        Ok(TAL {
            http_uri,
            rsync_uri,
            certificate,
        })
    }
}
