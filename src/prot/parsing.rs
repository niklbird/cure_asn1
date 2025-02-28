use prost::Message;
use std::fs::File;
use std::io::{Read, Write};
use std::str::from_utf8;
use prost_types::Timestamp;

use crate::rpki_utils::byt_to_in;
use crate::tree_parser::Tree; 
// Snapshot File
#[derive(PartialEq, Message, Clone)]
pub struct SnapshotFile { 
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(uint64, tag = "3")]
    pub serial: u64,
    #[prost(message, repeated, tag = "4")]
    pub cas: Vec<CertificateAuthority>,
}

#[derive(PartialEq, Message, Clone)]
pub struct CertificateAuthority {
    #[prost(string, tag = "1")]
    pub repo_uri: String,
    #[prost(message, repeated, tag = "2")]
    pub objects: Vec<ObjectEntry>,
}

#[derive(PartialEq, Message, Clone)]
pub struct ObjectEntry {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bytes, tag = "2")]
    pub content: Vec<u8>,
}

// Delta File
#[derive(PartialEq, Message, Clone)]
pub struct DeltaFile {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(uint64, tag = "3")]
    pub serial: u64,
    #[prost(message, repeated, tag = "4")]
    pub cas: Vec<CertificateAuthorityDelta>,
}

#[derive(PartialEq, Message, Clone)]
pub struct CertificateAuthorityDelta {
    #[prost(string, tag = "1")]
    pub repo_uri: String,
    #[prost(message, repeated, tag = "2")]
    pub added_objects: Vec<ObjectEntry>,
    #[prost(message, repeated, tag = "3")]
    pub updated_objects: Vec<UpdatedObject>,
}

#[derive(PartialEq, Message, Clone)]
pub struct UpdatedObject {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bytes, tag = "2")]
    pub old_hash: Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub new_content: Vec<u8>,
}

#[derive(PartialEq, Message, Clone)]
pub struct NotificationFile {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub session_id: String,
    #[prost(uint64, tag = "3")]
    pub serial: u64,
    #[prost(message, optional, tag = "4")]
    pub snapshot: Option<SnapshotReference>,
    #[prost(message, repeated, tag = "5")]
    pub deltas: Vec<DeltaReference>,
}

// Represents the snapshot reference in a notification file
#[derive(PartialEq, Message, Clone)]
pub struct SnapshotReference {
    #[prost(string, tag = "1")]
    pub uri: String,
    #[prost(string, tag = "2")]
    pub hash: String, // SHA-256 hash of the snapshot file
}

#[derive(PartialEq, Message, Clone)]
pub struct DeltaReference {
    #[prost(uint64, tag = "1")]
    pub serial: u64,
    #[prost(string, tag = "2")]
    pub uri: String,
    #[prost(string, tag = "3")]
    pub hash: String, // SHA-256 hash of the delta file
}

#[derive(PartialEq, Message, Clone)]
pub struct ROA {
    #[prost(uint64, tag = "1")]
    pub asn: u64,
    #[prost(message, repeated, tag = "2")]
    pub ip_and_fam: Vec<IpAndFam>,
    #[prost(message, tag = "3")]
    pub meta: Option<Meta>,
}

#[derive(PartialEq, Message, Clone)]
pub struct IpAndFam {
    #[prost(uint32, tag = "1")]
    pub fam: u32,
    #[prost(message, repeated, tag = "2")]
    pub ips: Vec<Vec<u8>>,
}

#[derive(PartialEq, Message, Clone)]
pub struct IpEntry {
    #[prost(bytes, tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, optional, tag = "2")]
    pub ml: Option<u32>,
}

#[derive(PartialEq, Message, Clone)]
pub struct Meta {
    #[prost(string, tag = "1")]
    pub oid: String,
    #[prost(uint64, tag = "2")]
    pub serial: u64,
    #[prost(message, tag = "3")]
    pub not_before: Option<Timestamp>,
    #[prost(message, tag = "4")]
    pub not_after: Option<Timestamp>,
    #[prost(bytes, optional, tag = "5")]
    pub ski: Option<Vec<u8>>,
}

#[derive(PartialEq, Message, Clone)]
pub struct Signature{
    #[prost(string, tag = "1")]
    pub algorithm: String,
    #[prost(bytes, optional, tag = "2")]
    pub parameters: Option<Vec<u8>>,
    #[prost(bytes, tag = "3")]
    pub signature: Vec<u8>,
}

#[derive(PartialEq, Message)]
pub struct Manifest{
    #[prost(message, tag = "1")]
    pub manifest_content: Option<ManifestContent>,
    #[prost(message, tag = "2")]
    pub meta: Option<Meta>,
    #[prost(message, tag = "3")]
    pub signature: Option<Signature>,
}

impl Manifest{
    pub fn get_signed_data(&self) -> Vec<u8>{
        let mut buffer = Vec::new();
        self.manifest_content.clone().unwrap().encode(&mut buffer).unwrap();
        self.meta.clone().unwrap().encode(&mut buffer).unwrap();
        buffer
    }

    pub fn add_signature(&mut self, sig: Vec<u8>){
        self.signature = Some(Signature{
            algorithm: "rsa".to_string(),
            parameters: None,
            signature: sig,
        });
    }
}

#[derive(PartialEq, Message, Clone)]
pub struct ManifestContent{
    #[prost(message,tag = "1")]
    pub hashes: Option<ManifestHashes>,
    #[prost(message, repeated, tag = "2")]
    pub revoced_certs: Vec<RevokedCert>,
}

#[derive(PartialEq, Message, Clone)]
pub struct ManifestHashes{
    #[prost(string, tag = "1")]
    pub hash_algorithm: String,
    #[prost(message,repeated, tag = "2")]
    pub hash_list: Vec<ManifestHash>,
}

#[derive(PartialEq, Message, Clone)]
pub struct ManifestHash{
    #[prost(string, tag = "1")]
    pub file_name: String,
    #[prost(bytes, tag = "2")]
    pub hash: Vec<u8>,
}


#[derive(PartialEq, Message, Clone)]
pub struct RevokedCert{
    #[prost(uint64, tag = "1")]
    pub serial: u64,
    #[prost(message, tag = "2")]
    pub revocation_time: Option<Timestamp>,
}

fn get_asn(tree: &Tree) -> u64{
    let raw = tree.get_raw_by_label("asID");

    if raw.is_none() {
        return 0;
    }

    let raw = raw.unwrap();

    let mut result: u64 = 0;
    for (_, &byte) in raw.iter().enumerate() {
        result = (result << 8) | (byte as u64);
    }
    
    
    result

}


pub fn get_crl_entries(_: &Tree) -> Vec<(u64, Timestamp)>{
    // crl.get_node_by_label("crlEntries").unwrap().children.iter().map(|&x| {
    //     let entry = &crl.tokens[&x];
    //     let serial = byt_to_in(&crl.tokens[&entry.children[0]].data);
    //     let time = Timestamp::from(crl.tokens[&entry.children[1]].data.clone());
    //     (serial, time)
    // }).collect()
    return vec![];

}

pub fn proto_from_mft(mft: &Tree, crl: &Tree) -> Manifest{
    let crl_entries = get_crl_entries(crl);
    let mut revoked_certs = Vec::new();
    for (serial, time) in crl_entries{
        let rev = RevokedCert{
            serial,
            revocation_time: Some(time),
        };
        revoked_certs.push(rev);
    }

    let mut manifest_hashes = vec![];

    for child in &mft.get_node_by_label("manifestHashes").unwrap().children{
        let child_tok = &mft.tokens[&child];
        let name = from_utf8( &mft.tokens[&child_tok.children[0]].data).unwrap_or_default().to_string();
        let hash = mft.tokens[&child_tok.children[1]].data.clone();
        let hash = ManifestHash{
            file_name: name,
            hash: hash[1..].to_vec(),
        };
        manifest_hashes.push(hash);
    }
    let manifest_hash = ManifestHashes{
        hash_algorithm: "sha256".to_string(),
        hash_list: manifest_hashes,
    };


    let serial = byt_to_in(&mft.get_raw_by_label("manifestNumber").unwrap());
    let meta = Meta{
        oid: "1.2.840.113549.1.9.16.1.26".to_string(),
        serial: serial,
        not_before: Some(Timestamp::date(2025, 1, 1).unwrap()),
        not_after: Some(Timestamp::date(2027, 1, 1).unwrap()),
        ski: Some(mft.get_raw_by_label("signerIdentifier").unwrap().clone()),
    };

    let manifest_content = ManifestContent{
        hashes: Some(manifest_hash),
        revoced_certs: revoked_certs,
    };

    let manifest = Manifest{
        manifest_content: Some(manifest_content),
        meta: Some(meta),
        signature: None,
    };

    manifest
}


pub fn proto_from_roa(roa: &Tree) -> Vec<u8>{
    println!("{:?}", roa);
    let ip_raw = roa.get_raw_by_label("ipAddrv4_0").unwrap();
    // let ip = IpEntry{
    //     ip: ip_raw,
    //     ml: None,
    // };

    let ip_and_fam = IpAndFam{
        fam: 4,
        ips: vec![ip_raw],
    };

    let random_u64 = 42;

    let meta = Meta{
        oid: "1.2.840.113549.1.9.16.1.24".to_string(),
        serial: random_u64,
        not_before: Some(Timestamp::date(2025, 1, 1).unwrap()),
        not_after: Some(Timestamp::date(2027, 1, 1).unwrap()),
        ski: None,
    };

    let object_info = ROA{
        asn: get_asn(roa),
        ip_and_fam: vec![ip_and_fam],
        meta: Some(meta),
    };

    let mut buffer = Vec::new();
    object_info.encode(&mut buffer).unwrap();
    buffer
}


// Helper function to serialize to binary
fn save_to_file<T: Message>(obj: &T, filename: &str) {
    let mut file = File::create(filename).expect("Failed to create file");
    let mut buffer = Vec::new();
    obj.encode(&mut buffer).expect("Failed to encode");
    file.write_all(&buffer).expect("Failed to write");
}

// Helper function to deserialize from binary
fn load_from_file<T: Message + Default>(filename: &str) -> T {
    let mut file = File::open(filename).expect("Failed to open file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file");
    T::decode(&*buffer).expect("Failed to decode")
}

// Example usage
pub fn example() {
    // Create Snapshot Example
    let snapshot = SnapshotFile {
        version: "1".to_string(),
        session_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        serial: 42,
        cas: vec![
            CertificateAuthority {
                repo_uri: "rsync://example.com/repo".to_string(),
                objects: vec![
                    ObjectEntry {
                        name: "example.roa".to_string(),
                        content: b"ROA_BINARY_DATA".to_vec(),
                    },
                    ObjectEntry {
                        name: "cert.cer".to_string(),
                        content: b"CERT_BINARY_DATA".to_vec(),
                    },
                ],
            },
        ],
    };

    // Create Delta Example
    let delta = DeltaFile {
        version: "1".to_string(),
        session_id: "123e4567-e89b-12d3-a456-426614174000".to_string(),
        serial: 43,
        cas: vec![
            CertificateAuthorityDelta {
                repo_uri: "rsync://example.com/repo".to_string(),
                added_objects: vec![
                    ObjectEntry {
                        name: "new_example.roa".to_string(),
                        content: b"NEW_ROA_BINARY_DATA".to_vec(),
                    },
                ],
                updated_objects: vec![
                    UpdatedObject {
                        name: "example.roa".to_string(),
                        old_hash: b"OLD_HASH_123".to_vec(),
                        new_content: b"UPDATED_ROA_BINARY_DATA".to_vec(),
                    },
                ],
            },
        ],
    };

    // Save to files
    save_to_file(&snapshot, "snapshot.bin");
    save_to_file(&delta, "delta.bin");

    // Load from files
    let loaded_snapshot: SnapshotFile = load_from_file("snapshot.bin");
    let loaded_delta: DeltaFile = load_from_file("delta.bin");

    // Print results
    println!("Loaded Snapshot: {:?}", loaded_snapshot);
    println!("Loaded Delta: {:?}", loaded_delta);
}
