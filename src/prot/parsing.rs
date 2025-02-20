use prost::Message;
use std::fs::File;
use std::io::{Read, Write};

// Snapshot File
#[derive(PartialEq, Message)]
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

#[derive(PartialEq, Message)]
pub struct CertificateAuthority {
    #[prost(string, tag = "1")]
    pub repo_uri: String,
    #[prost(message, repeated, tag = "2")]
    pub objects: Vec<ObjectEntry>,
}

#[derive(PartialEq, Message)]
pub struct ObjectEntry {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bytes, tag = "2")]
    pub content: Vec<u8>,
}

// Delta File
#[derive(PartialEq, Message)]
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

#[derive(PartialEq, Message)]
pub struct CertificateAuthorityDelta {
    #[prost(string, tag = "1")]
    pub repo_uri: String,
    #[prost(message, repeated, tag = "2")]
    pub added_objects: Vec<ObjectEntry>,
    #[prost(message, repeated, tag = "3")]
    pub updated_objects: Vec<UpdatedObject>,
}

#[derive(PartialEq, Message)]
pub struct UpdatedObject {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(bytes, tag = "2")]
    pub old_hash: Vec<u8>,
    #[prost(bytes, tag = "3")]
    pub new_content: Vec<u8>,
}

// Notification File
#[derive(PartialEq, Message)]
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
#[derive(PartialEq, Message)]
pub struct SnapshotReference {
    #[prost(string, tag = "1")]
    pub uri: String,
    #[prost(string, tag = "2")]
    pub hash: String, // SHA-256 hash of the snapshot file
}

// Represents a delta reference in a notification file
#[derive(PartialEq, Message)]
pub struct DeltaReference {
    #[prost(uint64, tag = "1")]
    pub serial: u64,
    #[prost(string, tag = "2")]
    pub uri: String,
    #[prost(string, tag = "3")]
    pub hash: String, // SHA-256 hash of the delta file
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
