use base64::{prelude::BASE64_STANDARD, Engine};
use rand::Rng;
use sha2::Digest;
use std::io::Cursor;
use xml::writer::{EmitterConfig, XmlEvent};

pub fn random_uuid() -> String {
    let rand_bytes: [u8; 16] = rand::thread_rng().gen();
    let hex_string: String = rand_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    hex_string
}


pub fn get_hash(data: Vec<u8>) -> String {
    let hash = sha2::Sha256::digest(&data);
    hex::encode(hash)
}

pub fn new_snapshot_and_notification(
    publish: Vec<(String, Vec<u8>)>,
    withdraws: Vec<String>,
    base_rrdp_dir: (&str, &str),
    domain: &str,
) -> (String, Vec<u8>, String, Vec<u8>) {
    let serial = 1;

    let session_id = random_uuid();
    let random = generate_random_bytes();

    let base_uri = format!("{}{}/{}", "https://", domain, base_rrdp_dir.0);
    let snapshot_uri = format!(
        "{}{}/{}/{}/snapshot.xml",
        &base_uri,
        &session_id,
        serial.to_string(),
        random
    );
    let notification_uri_l = format!("{}notification.xml", base_rrdp_dir.1);
    let snapshot_uri_l = format!(
        "{}{}/{}/{}/snapshot.xml",
        base_rrdp_dir.1,
        &session_id,
        serial.to_string(),
        random
    );

    let snap = create_snapshot(serial, &session_id, publish, withdraws).unwrap();
    let snap_hash = get_hash(snap.clone());
    let notif =
        create_notification(serial, &session_id, (&snapshot_uri, &snap_hash), None).unwrap();

    (snapshot_uri_l, snap, notification_uri_l, notif)
}

pub fn new_added_deltas(
    snap_publish: Vec<(String, Vec<u8>)>,
    snap_withdraws: Vec<String>,
    deltas: Vec<(Vec<(String, String, Vec<u8>)>, Vec<String>)>,
    previous_delta: Vec<(String, String, String)>, // Serial, uri, hash
    start_serial: u32,
    session_id: &str,
    base_rrdp_dir: &str,
    domain: &str,
) -> (String, Vec<u8>, String, Vec<u8>, Vec<(String, Vec<u8>)>) {
    let base_uri = format!("{}{}/{}", "https://", domain, base_rrdp_dir);

    let mut parsed_deltas = vec![];
    let mut serial = start_serial;
    let mut delta_for_notification = vec![];
    for delta in deltas {
        let parsed_delta = create_delta(serial, session_id, delta.0, delta.1).unwrap();

        let random = generate_random_bytes();
        let delta_uri = format!(
            "{}{}/{}/{}/delta.xml",
            &base_uri,
            &session_id,
            serial.to_string(),
            random
        );
        let delta_hash = get_hash(parsed_delta.clone());
        delta_for_notification.push((serial.to_string(), delta_uri, delta_hash));

        let delta_uri_l = format!(
            "{}{}/{}/{}/delta.xml",
            base_rrdp_dir,
            &session_id,
            serial.to_string(),
            random
        );
        parsed_deltas.push((delta_uri_l, parsed_delta));
        serial += 1;
    }

    // Decrease the serial in the end by one to revert the last increase (for which no delta exists)
    serial -= 1;

    let random = generate_random_bytes();

    let snapshot_uri = format!(
        "{}{}/{}/{}/snapshot.xml",
        &base_uri,
        &session_id,
        serial.to_string(),
        random
    );
    let notification_uri_l = format!("{}notification.xml", base_rrdp_dir);
    let snapshot_uri_l = format!(
        "{}{}/{}/{}/snapshot.xml",
        base_rrdp_dir,
        &session_id,
        serial.to_string(),
        random
    );

    let mut all_deltas = previous_delta.clone();
    all_deltas.extend(delta_for_notification.clone());
    all_deltas.reverse();
    let snap = create_snapshot(serial, &session_id, snap_publish, snap_withdraws).unwrap();
    let snap_hash = get_hash(snap.clone());
    let notif = create_notification(
        serial,
        &session_id,
        (&snapshot_uri, &snap_hash),
        Some(all_deltas),
    )
    .unwrap();

    (
        snapshot_uri_l,
        snap,
        notification_uri_l,
        notif,
        parsed_deltas,
    )
}

pub fn create_snapshot(
    serial: u32,
    session_id: &str,
    publishes: Vec<(String, Vec<u8>)>,
    withdraws: Vec<String>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("snapshot")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    for (uri, data) in publishes {
        writer.write(XmlEvent::start_element("publish").attr("uri", &uri))?;
        writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(data)))?;
        writer.write(XmlEvent::end_element())?;
    }

    for uri in withdraws {
        writer.write(XmlEvent::start_element("withdraw").attr("uri", &uri))?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

pub fn create_notification(
    serial: u32,
    session_id: &str,
    snap_uri_hash: (&str, &str),
    deltas_serial_uri_hash: Option<Vec<(String, String, String)>>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("notification")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    writer.write(
        XmlEvent::start_element("snapshot")
            .attr("uri", snap_uri_hash.0)
            .attr("hash", snap_uri_hash.1),
    )?;
    writer.write(XmlEvent::end_element())?;

    for (serial, uri, hash) in deltas_serial_uri_hash.unwrap_or(vec![]) {
        writer.write(
            XmlEvent::start_element("delta")
                .attr("serial", &serial)
                .attr("uri", &uri)
                .attr("hash", &hash),
        )?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

pub fn create_delta(
    serial: u32,
    session_id: &str,
    publishes: Vec<(String, String, Vec<u8>)>,
    withdraws: Vec<String>,
) -> xml::writer::Result<Vec<u8>> {
    let mut output = Cursor::new(Vec::new());
    let mut writer = EmitterConfig::new()
        .perform_indent(true)
        .create_writer(&mut output);

    writer.write(
        XmlEvent::start_element("delta")
            .attr("xmlns", "http://www.ripe.net/rpki/rrdp")
            .attr("version", "1")
            .attr("serial", &serial.to_string())
            .attr("session_id", session_id),
    )?;

    for (uri, hash, data) in publishes {
        if hash == "" {
            writer.write(XmlEvent::start_element("publish").attr("uri", &uri))?;
        } else {
            writer.write(
                XmlEvent::start_element("publish")
                    .attr("uri", &uri)
                    .attr("hash", &hash),
            )?;
        }
        writer.write(XmlEvent::characters(&BASE64_STANDARD.encode(data)))?;
        writer.write(XmlEvent::end_element())?;
    }

    for uri in withdraws {
        writer.write(XmlEvent::start_element("withdraw").attr("uri", &uri))?;
        writer.write(XmlEvent::end_element())?;
    }

    writer.write(XmlEvent::end_element())?;

    let output = output.into_inner();
    Ok(output)
}

#[derive(Clone)]
pub struct RRDPEntry {
    pub uri: String,
    pub hash: Option<String>,
    pub data: Vec<u8>,
    pub typ: String,
    pub serial: Option<u32>,
}

pub struct XMLSnapshot {
    pub serial: u32,
    pub session_id: String,
    pub entries: Vec<RRDPEntry>,
}

impl XMLSnapshot {
    pub fn get_entry(&self, uri: &str) -> Option<&RRDPEntry> {
        for entry in &self.entries {
            if entry.uri == uri {
                return Some(entry);
            }
        }
        return None;
    }

    pub fn get_all_entries_raw(&self) -> Vec<(String, Vec<u8>)> {
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entries.push((entry.uri.clone(), entry.data.clone()));
        }
        return entries;
    }
}

pub struct XMLNotification {
    pub serial: u32,
    pub session_id: String,
    pub snapshot_uri: Option<RRDPEntry>,
    pub deltas: Vec<RRDPEntry>,
}

impl XMLNotification {
    pub fn get_snapshot_uri(&self) -> Option<String> {
        if self.snapshot_uri.is_some() {
            return Some(self.snapshot_uri.clone().unwrap().uri);
        }
        return None;
    }

    pub fn get_snapshot_uri_local(&self) -> String {
        let uri = self.get_snapshot_uri().unwrap();
        let uri = uri.replace("https://", "");
        let uri = uri.split("/").collect::<Vec<&str>>()[1..].join("/");
        return uri;
    }

    pub fn get_deltas(&self) -> Vec<(String, String, String)> {
        let mut deltas = vec![];
        for delta in &self.deltas {
            deltas.push((
                delta.serial.clone().unwrap_or(0).to_string(),
                delta.uri.clone(),
                delta.hash.clone().unwrap_or("".to_string()),
            ));
        }
        return deltas;
    }
}

pub fn parse_notification(xml_data: &str) -> Option<XMLNotification> {
    let root: Result<minidom::Element, _> = xml_data.parse();
    if root.is_err() {
        return None;
    }
    let root = root.unwrap();

    let mut snapshot = None;
    let mut deltas = vec![];
    for c in root.children() {
        if c.name() == "snapshot" {
            let uri = c.attr("uri").unwrap();
            let hash = c.attr("hash").unwrap();
            snapshot = Some(RRDPEntry {
                uri: uri.to_string(),
                hash: Some(hash.to_string()),
                data: vec![],
                typ: "snapshot".to_string(),
                serial: None,
            });
        } else {
            let uri = c.attr("uri").unwrap_or("none");
            let serial = c.attr("serial").unwrap_or("0").parse().unwrap_or(0);
            let hash = c.attr("hash").unwrap_or("none");

            let typ = c.name();
            let entry = RRDPEntry {
                uri: uri.to_string(),
                hash: Some(hash.to_string()),
                data: vec![],
                typ: typ.to_string(),
                serial: Some(serial),
            };
            deltas.push(entry);
        }
    }

    let notification = XMLNotification {
        serial: root.attr("serial").unwrap().parse().unwrap(),
        session_id: root.attr("session_id").unwrap().to_string(),
        snapshot_uri: snapshot,
        deltas,
    };
    
    return Some(notification);
}

pub fn parse_snapshot(xml_data: &str) -> Option<XMLSnapshot> {
    let root: Result<minidom::Element, _> = xml_data.parse();
    
    if root.is_err() {
        return None;
    }
    let root = root.unwrap();

    let mut entries = vec![];
    for c in root.children() {
        let uri = c.attr("uri").unwrap();
        let typ = c.name();
        let data_raw = c.text();
        let data_raw = data_raw.trim();
        let data_raw = data_raw.replace("\n", "");
        let data = BASE64_STANDARD.decode(data_raw).unwrap_or(vec![]);

        let entry = RRDPEntry {
            uri: uri.to_string(),
            hash: None,
            data,
            typ: typ.to_string(),
            serial: None,
        };
        entries.push(entry);
    }

    let snapshot = XMLSnapshot {
        serial: root.attr("serial").unwrap().parse().unwrap(),
        session_id: root.attr("session_id").unwrap().to_string(),
        entries,
    };

    return Some(snapshot);
}


pub fn generate_random_bytes() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}
