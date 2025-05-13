/*
Label an ASN.1 syntax tree. Currently only RPKI labels are supported, which includes most X.509 certificate extensions.
*/

use std::collections::HashMap;
use crate::labeling::LabelName::*;
use crate::tree_parser::{Tree, Types};

pub fn parse_oid(data: &Vec<u8>) -> String {
    let mut oid = String::new();

    if data.is_empty() {
        return oid;
    }

    // Handle the first byte: first two OID components
    let first_byte = data[0];
    oid.push_str(&format!("{}.", first_byte / 40));
    oid.push_str(&format!("{}", first_byte % 40));

    let mut value = 0u32;
    for &byte in &data[1..] {
        value = (value << 7) | (byte & 0x7F) as u32;
        if (byte & 0x80) == 0 {
            oid.push_str(&format!(".{}", value));
            value = 0;
        }
    }

    oid
}

/*
The following functions generate dynamic labels for fields that are not statically defined.
*/
fn label_fn_encoded_content<'a>(id: usize, tree: &Tree) -> LabelObject {
    let children = label_enc_content_inner(&tree.obj_type);
    let c = &tree.get_node(id).unwrap().children;

    // No children or not a nested octetstring -> Just return normal
    if c.len() == 0 || tree.get_node(c[0]).unwrap().tag != Types::OctetString {
        return LabelObject::new(Some("eContentOuterOctet".to_string()), children);
    }

    let inner_oc = LabelObject::new(Some("eContentInnerOctet".to_string()), children);
    let outer = LabelObject::new(Some("eContentOuterOctet".to_string()), vec![inner_oc]);
    outer
}

fn label_fn_signed_attrs<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let signed_attrs_map = label_signed_attributes_rpki();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if signed_attrs_map.contains_key(&oid.as_str()) {
            let label_obj = signed_attrs_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("signerSignedAttributesField".to_string()), labels)
}

fn label_fn_extensions<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let ext_map = label_extensions_rpki();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if ext_map.contains_key(&oid.as_str()) {
            let label_obj = ext_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("extensions".to_string()), labels)
}

fn label_fn_extension_subject_info_access_seq<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    let ext_map = label_extension_subject_info_access();

    for child_id in &tree.get_node(id).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() == 0 {
            continue;
        }
        let oid = parse_oid(&tree.get_node(child.children[0]).unwrap().data);
        if ext_map.contains_key(&oid.as_str()) {
            let label_obj = ext_map.get(&oid.as_str()).unwrap();
            labels.push(label_obj.clone());
        } else {
            println!("Unknown Extension OID: {}", oid);
            labels.push(LabelObject::new(None, vec![]));
        }
    }
    LabelObject::new(Some("subjectInfoAccessSeq".to_string()), labels)
}

/// Creates a dynamic [`LabelObject`] for the RFC3779 IPAddrBlocks certificate extension.
fn label_fn_extension_ip_addr_blocks_seq(id: usize, tree: &Tree) -> LabelObject {
    // let  mut labels = Vec::new();
    //
    // // IPAddrBlocks        ::= SEQUENCE OF IPAddressFamily
    // let node_IpAddrBlocks = tree.get_node(id).unwrap();
    //
    // for child_id in &node_IpAddrBlocks.children {
    //     // IPAddressFamily     ::= SEQUENCE {    -- AFI & optional SAFI --
    //     //       addressFamily        OCTET STRING (SIZE (2..3)),
    //     //       ipAddressChoice      IPAddressChoice }
    //     let child_nod = tree.get_node(*child_id).unwrap();
    //
    //     let ip_afi = child_nod.children[0];
    //     let ip_address_choice = child_nod.children[1];
    //
    //     let suffix = match tree.get_node(ip_afi).unwrap().data.as_slice() {
    //         [0, 1] => "v4",
    //         [0, 2] => "v6",
    //         _ => "",
    //     };
    //
    //     let ip_afi_l = LabelObject::new(Some(format!("ipAddrBlocksFamily{}", suffix)), vec![]);
    //
    //     if tree.get_node(ip_address_choice).unwrap().tag == 0 {
    //
    //     }
    //
    //     let mut child_counter = 0;
    //     let mut child_labels = vec![];
    //
    //     for ip_address_choice_val in
    //
    // }
    //
    // a
    return LabelObject::new(Some("roaContent".to_string()), vec![]);
}

fn label_fn_roa_ip_seq<'a>(id: usize, tree: &Tree) -> LabelObject {
    let mut labels = Vec::new();

    if tree.get_node(id).unwrap().children.len() < 2 {
        return LabelObject::new(Some("roaContent".to_string()), vec![]);
    }

    let as_id = LabelObject::new(Some("asID".to_string()), vec![]);

    for child_id in &tree.get_node(tree.get_node(id).unwrap().children[1]).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();

        let ip_afi = child.children[0];

        let ip_addresses = child.children[1];
        let suffix;
        if tree.get_node(ip_afi).unwrap().data == vec![0, 1]{
            suffix = "v4";
        }
        else{
            suffix = "v6";
        }

        let ip_afi_l = LabelObject::new(Some(format!("ipAFI{}", suffix)), vec![]);

        let mut ip_counter = 0;
        let mut child_labels = vec![];

        for ip_val in &tree.get_node(ip_addresses).unwrap().children{
            let ip_node = tree.get_node(*ip_val).unwrap();
            let ip = format!("ipAddrBlock{}_{}", suffix, ip_counter);

            let mut ip_labels = vec![];
            
            let lab = format!("ipAddr{}_{}", suffix, ip_counter);
            let label_ml = format!("ipMl{}_{}", suffix, ip_counter);


            if ip_node.children.len() == 1{
                ip_labels.push(LabelObject::new(Some(lab), vec![]));
            }
            else{
                ip_labels.push(LabelObject::new(Some(lab), vec![]));

                ip_labels.push(LabelObject::new(Some(label_ml), vec![]));
            }

            child_labels.push(LabelObject::new(Some(ip), ip_labels));
            ip_counter += 1;
        }
        
        let la = LabelObject::new(Some(format!("ipAddrBlocks{}", suffix)), child_labels);
        let afi_and_ips = LabelObject::new(Some(format!("ipAddrBlocks{}Seq", suffix)), vec![ip_afi_l, la]);

        labels.push(afi_and_ips);
    }

    LabelObject::new(Some("roaContent".to_string()), vec![as_id, LabelObject::new(Some("ipAddrBlocks".to_string()), labels)])
}

fn label_fn_mft<'a>(id: usize, tree: &Tree) -> LabelObject {
    let manifest_number = LabelObject::new(Some("manifestNumber".to_string()), vec![]);

    let this_update = LabelObject::new(Some("thisUpdate".to_string()), vec![]);

    let next_update = LabelObject::new(Some("nextUpdate".to_string()), vec![]);

    let hash_algo = LabelObject::new(Some("manifestHashAlgorithm".to_string()), vec![]);

    let last = tree.get_node(id).unwrap().children.last();
    if last.is_none(){
        return LabelObject::new(Some("mftContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo]);
    }

    let mut val_counter = 0;
    let mut entries = vec![];
    for child_id in &tree.get_node(*last.unwrap()).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() != 2 {
            continue;
        }
        let name_label = LabelObject::new(Some(format!("mftHashName_{}", val_counter)), vec![]);
        let hash_label = LabelObject::new(Some(format!("mftHashValue_{}", val_counter)), vec![]);
        val_counter += 1;
        let entry = LabelObject::new(Some(format!("mftEntry_{}", val_counter)), vec![name_label, hash_label]);
        entries.push(entry);
    }
    let hashes = LabelObject::new(Some("manifestHashes".to_string()), entries);
    let enc = LabelObject::new(Some("mftContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo, hashes]);
    enc
    
}

#[derive(Clone, Debug, PartialEq, Eq, Copy, serde::Serialize, serde::Deserialize, Hash)]
pub enum LabelName {

    //SignedObjectXYZ,

    Certificate,

    /// Certificate Fields
    CertFldVersionSeq,
    CertFldVersion,
    CertFldSerialNumber,
    CertFldSignature,
    CertFldSignatureAlgorithm,
    CertFldSignatureParameters,
    CertFldIssuer,
    /// RelativeDistinguishedName SET
    CertFldIssuerRdnSet,
    CertFldIssuerAttributeTypeAndValue,
    CertFldIssuerAttributeType,
    CertFldIssuerAttributeValue,
    CertFldExtensions,
    CertFldExtensionsSeq,
    CertFldValidity,
    CertFldValidityNotBefore,
    CertFldValidityNotAfter,
    CertFldSubject,
    /// RelativeDistinguishedName SET
    CertFldSubjectRdnSet,
    CertFldSubjectAttributeTypeAndValue,
    CertFldSubjectAttributeType,
    CertFldSubjectAttributeValue,
    CertFldSubjectPublicKeyInfo,
    CertFldSubjectPublicKeyInfoAlgorithm,
    CertFldSubjectPublicKeyInfoAlgorithmId,
    CertFldSubjectPublicKeyInfoAlgorithmParameters,
    CertFldSubjectPublicKeyInfoPublicKey,

    // revokedCertificates
    CrlFldEntries,

    /// Authority Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtAki,
    CertExtAkiOid,
    CertExtAkiValue,
    CertExtAkiSeq,
    CertExtAkiKeyIdentifier,

    /// Subject Key Identifier [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2
    CertExtSki,
    CertExtSkiOid,
    CertExtSkiValue,
    CertExtSkiKeyIdentifier,

    /// Key Usage [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3
    CertExtKu,
    CertExtKuOid,
    CertExtKuCritc,
    CertExtKuValue,
    CertExtKuBitstring,

    /// Certificate Policies [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
    CertExtCp,
    CertExtCpOid,
    CertExtCpCritc,
    CertExtCpValue,
    CertExtCpSeq,
    CertExtCpPolicyInformation,
    CertExtCpPolicyIdentifierOid,
    CertExtCpPolicyQualifiers,
    CertExtCpPolicyQualifierInfo,
    CertExtCpPolicyQualifierOid, // TODO Certification Practice Statement (CPS) pointer qualifier type
    CertExtCpPolicyQualifier,

    /// Basic Constraints Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9
    CertExtBc,
    CertExtBcOid,
    CertExtBcCritc,
    CertExtBcValue,
    CertExtBcSeq,
    CertExtBcCa,

    /// CRL Distribution Points Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.13
    CertExtCrldp,
    CertExtCrldpOid,
    CertExtCrldpValue,
    CertExtCrldpSeq,
    CertExtCrldpDistributionPoint,
    CertExtCrldpDistributionPointName,
    CertExtCrldpFullName,
    CertExtCrldpUri,

    /// Authority Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.1
    CertExtAia,
    CertExtAiaOid,
    CertExtAiaValue,
    CertExtAiaSeq,
    CertExtAiaAccessDescription,
    CertExtAiaCaIssuersOid,
    CertExtAiaCaIssuersUri,

    /// Subject Information Access Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.2.2
    CertExtSia,
    CertExtSiaOid,
    CertExtSiaValue,
    CertExtSiaSeq,
    CertExtSiaAccessDescription,
    CertExtSiaCaRepositoryOid,
    CertExtSiaCaRepositoryUri,
    CertExtSiaRpkiManifestOid,
    CertExtSiaRpkiManifestUri,
    CertExtSiaNotificationOid,
    CertExtSiaNotificationUri,
    CertExtSiaSignedObjectOid,
    CertExtSiaSignedObjectUri,

    /// IP Address Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-2
    CertExtIp,
    CertExtIpOid,
    CertExtIpCritc,
    CertExtIpValue,
    CertExtIpSeq,
    CertExtIpAddressFamily,
    CertExtIpAddressFamilyId,
    CertExtIpAddressChoice(u32),
    CertExtIpAddressPrefix(u32),
    CertExtIpAddressRange(u32),
    CertExtIpAddressRangeMin(u32),
    CertExtIpAddressRangeMax(u32),

    /// Autonomous System Identifier Delegation Extension [RFC3779]
    ///
    /// [RFC3779]: https://www.rfc-editor.org/rfc/rfc3779.html#section-3
    CertExtAsid,
    CertExtAsidOid,
    CertExtAsidCritc,
    CertExtAsidValue,
    CertExtAsidSeq,
    CertExtAsidAsnum,
    CertExtAsidAsnumIdOrRange,
    CertExtAsidAsnumRageMin,
    CertExtAsidAsnumRageMax,
    CertExtAsidRdi,
    CertExtAsidRdiIdOrRange,
    CertExtAsidRdiRangeMin,
    CertExtAsidRdiRangeMax,

    /// CRL Number Extension [RFC5280]
    ///
    /// [RFC5280]: https://www.rfc-editor.org/rfc/rfc5280.html#section-5.2.3
    CrlExtCrln,
    CrlExtCrlnOid,
    CrlExtCrlnValue,

    //RoaXYZ,

    //ManifestXYZ,

    // TODO ghostbuster, ASPA, etc.
}

impl LabelName {
    pub fn short_label(&self) -> &'static str {
        use LabelName::*;
        match self {
            Certificate => "certificate",

            CertFldVersionSeq => "certVersionSeq",
            CertFldVersion => "certVersion",
            CertFldSerialNumber => "certSerialNumber",
            CertFldSignature => "certSignature",
            CertFldSignatureAlgorithm => "certSignatureAlgorithm",
            CertFldSignatureParameters => "certSignatureParameters",
            CertFldIssuer => "certIssuer",
            CertFldIssuerRdnSet => "certIssuerRdnSet",
            CertFldIssuerAttributeTypeAndValue => "certIssuerAttributeTypeAndValue",
            CertFldIssuerAttributeType => "certIssuerAttributeType",
            CertFldIssuerAttributeValue => "certIssuerAttributeValue",
            CertFldExtensions => "certExtensions",
            CertFldExtensionsSeq => "certExtensionsSeq",
            CertFldValidity => "certValidity",
            CertFldValidityNotBefore => "certNotBefore",
            CertFldValidityNotAfter => "certNotAfter",
            CertFldSubject => "certSubject",
            CertFldSubjectRdnSet => "certSubjectRdnSet",
            CertFldSubjectAttributeTypeAndValue => "certSubjectAttributeTypeAndValue",
            CertFldSubjectAttributeType => "certSubjectAttributeType",
            CertFldSubjectAttributeValue => "certSubjectAttributeValue",
            CertFldSubjectPublicKeyInfo => "certSubjectPublicKeyInfo",
            CertFldSubjectPublicKeyInfoAlgorithm => "certSubjectPublicKeyInfoAlgorithm",
            CertFldSubjectPublicKeyInfoAlgorithmId => "certSubjectPublicKeyInfoAlgorithmId",
            CertFldSubjectPublicKeyInfoAlgorithmParameters => "certSubjectPublicKeyInfoAlgorithmParameters",
            CertFldSubjectPublicKeyInfoPublicKey => "certSubjectPublicKeyInfoPublicKey",
            CrlFldEntries => "crlEntries",

            // Authority Key Identifier
            CertExtAki => "authorityKeyIdentifier",
            CertExtAkiOid => "authorityKeyIdentifierOid",
            CertExtAkiValue => "authorityKeyIdentifierValue",
            CertExtAkiSeq => "authorityKeyIdentifierSeq",
            CertExtAkiKeyIdentifier => "authorityKeyIdentifierKeyIdentifier",

            // Subject Key Identifier
            CertExtSki => "subjectKeyIdentifier",
            CertExtSkiOid => "subjectKeyIdentifierOid",
            CertExtSkiValue => "subjectKeyIdentifierValue",
            CertExtSkiKeyIdentifier => "subjectKeyIdentifierKeyIdentifier",

            // Key Usage
            CertExtKu => "keyUsage",
            CertExtKuOid => "keyUsageOid",
            CertExtKuCritc => "keyUsageValue",
            CertExtKuValue => "keyUsageValue",
            CertExtKuBitstring => "keyUsageBitstring",

            // Certificate Policies
            CertExtCp => "certificatePolicies",
            CertExtCpOid => "certificatePoliciesOid",
            CertExtCpCritc => "certificatePoliciesCritc",
            CertExtCpValue => "certificatePoliciesValue",
            CertExtCpSeq => "certificatePoliciesSeq",
            CertExtCpPolicyInformation => "cpPolicyInformation",
            CertExtCpPolicyIdentifierOid => "cpPolicyIdentifierOid",
            CertExtCpPolicyQualifiers => "cpPolicyQualifiers",
            CertExtCpPolicyQualifierInfo => "cpPolicyQualifierInfo",
            CertExtCpPolicyQualifierOid => "cpPolicyQualifierOid",
            CertExtCpPolicyQualifier => "cpPolicyQualifier",

            // Basic Constraints
            CertExtBc => "basicConstraints",
            CertExtBcOid => "basicConstraintsOid",
            CertExtBcCritc => "basicConstraintsCritc",
            CertExtBcValue => "basicConstraintsValue",
            CertExtBcSeq => "basicConstraintsSeq",
            CertExtBcCa => "basicConstraintsCa",

            // CRL Distribution Points
            CertExtCrldp => "crlDistributionPoints",
            CertExtCrldpOid => "crlDistributionPointsOid",
            CertExtCrldpValue => "crlDistributionPointsValue",
            CertExtCrldpSeq => "crlDistributionPointsSeq",
            CertExtCrldpDistributionPoint => "crlDistributionPointsDistributionPoint",
            CertExtCrldpDistributionPointName => "crlDistributionPointsDistributionPointName",
            CertExtCrldpFullName => "crlDistributionPointsFullName",
            CertExtCrldpUri => "crlDistributionPointsUri",

            // Authority Information Access
            CertExtAia => "authorityInformationAccess",
            CertExtAiaOid => "authorityInformationAccessOid",
            CertExtAiaValue => "authorityInformationAccessValue",
            CertExtAiaSeq => "authorityInformationAccessSeq",
            CertExtAiaAccessDescription => "aiaAccessDescription",
            CertExtAiaCaIssuersOid => "aiaCaIssuersOid",
            CertExtAiaCaIssuersUri => "aiaCaIssuersUri",

            // Subject Information Access
            CertExtSia => "subjectInformationAccess",
            CertExtSiaOid => "subjectInformationAccessOid",
            CertExtSiaValue => "subjectInformationAccessValue",
            CertExtSiaSeq => "subjectInformationAccessSeq",
            CertExtSiaAccessDescription => "siaAccessDescription",
            CertExtSiaCaRepositoryOid => "siaCaRepository",
            CertExtSiaCaRepositoryUri => "siaCaRepositoryURI",
            CertExtSiaRpkiManifestOid => "siaRpkiManifest",
            CertExtSiaRpkiManifestUri => "siaRpkiManifestURI",
            CertExtSiaNotificationOid => "siaNotification",
            CertExtSiaNotificationUri => "siaNotificationURI",
            CertExtSiaSignedObjectOid => "siaSignedObject",
            CertExtSiaSignedObjectUri => "siaSignedObjectURI",

            // IP Address Delegation Extension
            CertExtIp => "ipAddressDelegation",
            CertExtIpOid => "ipAddressDelegationOid",
            CertExtIpCritc => "ipAddressDelegationCritc",
            CertExtIpValue => "ipAddressDelegationValue",
            CertExtIpSeq => "ipAddressDelegationSeq",
            CertExtIpAddressFamily => "ipAddressDelegationFamily",
            CertExtIpAddressFamilyId => "ipAddressDelegationFamilyId",
            CertExtIpAddressChoice(ipv) if *ipv == 1 => "ipAddressDelegation_v4_ipAddressChoice",
            CertExtIpAddressChoice(ipv) if *ipv == 2 => "ipAddressDelegation_v6_ipAddressChoice",
            CertExtIpAddressChoice(_ipv) => "ipAddressDelegation_ipAddressChoice",
            CertExtIpAddressPrefix(ipv) if *ipv == 1 => "ipAddressDelegation_v4_prefix",
            CertExtIpAddressPrefix(ipv) if *ipv == 2 => "ipAddressDelegation_v6_prefix",
            CertExtIpAddressPrefix(_ipv) => "ipAddressDelegation_prefix",
            CertExtIpAddressRange(ipv) if *ipv == 1 => "ipAddressDelegation_v4_range",
            CertExtIpAddressRange(ipv) if *ipv == 2 => "ipAddressDelegation_v6_range",
            CertExtIpAddressRange(_ipv) => "ipAddressDelegation_range",
            CertExtIpAddressRangeMin(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMin",
            CertExtIpAddressRangeMin(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMin",
            CertExtIpAddressRangeMin(_ipv) => "ipAddressDelegation_rangeMin",
            CertExtIpAddressRangeMax(ipv) if *ipv == 1 => "ipAddressDelegation_v4_rangeMax",
            CertExtIpAddressRangeMax(ipv) if *ipv == 2 => "ipAddressDelegation_v6_rangeMax",
            CertExtIpAddressRangeMax(_ipv) => "ipAddressDelegation_rangeMax",

            // Autonomous System Identifier Delegation Extension
            CertExtAsid => "asIdDelegation",
            CertExtAsidOid => "asIdDelegationOid",
            CertExtAsidCritc => "asIdDelegationCritc",
            CertExtAsidValue => "asIdDelegationValue",
            CertExtAsidSeq => "asIdDelegationSeq",
            CertExtAsidAsnum => "asIdDelegationAsnum",
            CertExtAsidAsnumIdOrRange => "asIdDelegationAsnumIdOrRange",
            CertExtAsidAsnumRageMin => "asIdDelegationAsnumRangeMin",
            CertExtAsidAsnumRageMax => "asIdDelegationAsnumRageMax",
            CertExtAsidRdi => "asIdDelegationRdi",
            CertExtAsidRdiIdOrRange => "asIdDelegationRdiOrRange",
            CertExtAsidRdiRangeMin => "asIdDelegationRdiRangeMin",
            CertExtAsidRdiRangeMax => "asIdDelegationRdiRangeMax",

            // CRL Number Extension
            CrlExtCrln => "crlNumber",
            CrlExtCrlnOid => "crlNumberOid",
            CrlExtCrlnValue => "crlNumberValue",
        }
    }

    /// Returns the OID associated with a [`LabelName`] (indicated by ending with -Oid).
    ///
    /// Returns [`None`], if no OID is associated with this [`LabelName`].
    pub fn oid(&self) -> Option<&'static str> {
        match self {
            CertExtAkiOid => Some("2.5.29.35"),
            CertExtSkiOid => Some("2.5.29.14"),
            CertExtKuOid => Some("2.5.29.15"),
            CertExtCpOid => Some("2.5.29.32"),
            CertExtBcOid => Some("2.5.29.19"),
            CertExtCrldpOid => Some("2.5.29.31"),
            CertExtAiaOid => Some("1.3.6.1.5.5.7.1.1"),
            CertExtAiaCaIssuersOid => Some("1.3.6.1.5.5.7.48.2"),
            CertExtSiaOid => Some("1.3.6.1.5.5.7.1.11"),
            CertExtSiaCaRepositoryOid => Some("1.3.6.1.5.5.7.48.5"),
            CertExtSiaRpkiManifestOid => Some("1.3.6.1.5.5.7.48.10"),
            CertExtSiaNotificationOid => Some("1.3.6.1.5.5.7.48.13"),
            CertExtSiaSignedObjectOid => Some("1.3.6.1.5.5.7.48.11"),
            CertExtIpOid => Some("1.3.6.1.5.5.7.1.7"),
            CertExtAsidOid => Some("1.3.6.1.5.5.7.1.8"),
            CrlExtCrlnOid => Some("2.5.29.20"),
            _ => None,
        }
    }
}

/// Uniquely identifies a node in the ASN.1 tree.
///
/// A label consists of a [`LabelName`], which is uniquely derived from the ASN.1 object
/// specification(s) and an index to differentiate nodes of the same name.
#[derive(Clone, Debug, PartialEq, Eq, Copy, serde::Serialize, serde::Deserialize, Hash)]
pub struct Label {
    name: LabelName,
    index: usize,
}

impl Label {
    pub fn new(name: LabelName, index: usize) -> Self {
        Self {
            name,
            index,
        }
    }
}

impl From<LabelName> for Label {
    fn from(name: LabelName) -> Label {
        Label { name, index: 0 }
    }
}

/// TODO document this
#[derive(Clone, Debug)]
pub struct LabelObject {
    pub label: Option<Label>,
    pub children: Vec<LabelObject>,
    pub label_function: Option<fn(usize, &Tree) -> LabelObject>,
}

impl<'a> LabelObject {
    pub fn new(label: Option<Label>, children: Vec<LabelObject>) -> LabelObject {
        LabelObject {
            label,
            children,
            label_function: None,
        }
    }
}

impl<'a> From<LabelName> for LabelObject {
    fn from(value: LabelName) -> Self {
        LabelObject::new(Some(value.into()), vec![])
    }
}

pub fn label_extension_subject_info_access() -> HashMap<&'static str, LabelObject> {
    let mut i = 0;
    let ca_repo_ext = LabelObject::new(
        Some(Label::new(CertExtSiaAccessDescription, i)),
        vec![
            CertExtSiaCaRepositoryOid.into(),
            CertExtSiaCaRepositoryUri.into(),
        ],
    );

    i += 1;
    let manifest_uri = LabelObject::new(
        Some(Label::new(CertExtSiaAccessDescription, i)),
        vec![
            CertExtSiaRpkiManifestOid.into(),
            CertExtSiaRpkiManifestUri.into(),
        ],
    );

    i += 1;
    let notification_uri = LabelObject::new(
        Some(Label::new(CertExtSiaAccessDescription, i)),
        vec![
            CertExtSiaNotificationOid.into(),
            CertExtSiaNotificationUri.into(),
        ],
    );

    i += 1;
    let signed_object_uri = LabelObject::new(
        Some(Label::new(CertExtSiaAccessDescription, i)),
        vec![
            CertExtSiaSignedObjectOid.into(),
            CertExtSiaSignedObjectUri.into(),
        ],
    );

    let mut map = HashMap::new();
    map.insert(CertExtSiaCaRepositoryOid.oid().unwrap(), ca_repo_ext);
    map.insert(CertExtSiaRpkiManifestOid.oid().unwrap(), manifest_uri);
    map.insert(CertExtSiaNotificationOid.oid().unwrap(), notification_uri);
    map.insert(CertExtSiaSignedObjectOid.oid().unwrap(), signed_object_uri);

    map
}

pub fn label_extensions_rpki() -> HashMap<&'static str, LabelObject> {
    let basic_constraints = LabelObject::new(
        Some(CertExtBc.into()),
        vec![
            CertExtBcOid.into(),
            CertExtBcCritc.into(),
            LabelObject::new(
                Some(CertExtBcValue.into()),
                vec![LabelObject::new(
                    Some(CertExtBcSeq.into()),
                    vec![CertExtBcCa.into()],
                )],
            ),
        ],
    );

    let subject_key_identifier = LabelObject::new(
        Some(CertExtSki.into()),
        vec![
            CertExtSkiOid.into(),
            LabelObject::new(
                Some(CertExtSkiValue.into()),
                vec![CertExtSkiKeyIdentifier.into()],
            ),
        ],
    );

    let authority_key_identifier = LabelObject::new(
        Some(CertExtAki.into()),
        vec![
            CertExtAkiOid.into(),
            LabelObject::new(
                Some(CertExtAkiValue.into()),
                vec![LabelObject::new(
                    Some(CertExtAkiSeq.into()),
                    vec![CertExtAkiKeyIdentifier.into()],
                )],
            ),
        ],
    );

    let key_usage = LabelObject::new(
        Some(CertExtKu.into()),
        vec![
            CertExtKuOid.into(),
            CertExtKuCritc.into(),
            LabelObject::new(
                Some(CertExtKuValue.into()),
                vec![CertExtKuBitstring.into()],
            ),
        ],
    );

    let crl_distribution_points = LabelObject::new(
        Some(CertExtCrldp.into()),
        vec![
            CertExtCrldpOid.into(),
            LabelObject::new(
                Some(CertExtCrldpValue.into()),
                vec![LabelObject::new(
                    Some(CertExtCrldpSeq.into()),
                    vec![LabelObject::new(
                        Some(CertExtCrldpDistributionPoint.into()),
                        vec![LabelObject::new(
                            Some(CertExtCrldpDistributionPointName.into()),
                            vec![LabelObject::new(
                                Some(CertExtCrldpFullName.into()),
                                // TODO allow multiple entries for FullName
                                vec![CertExtCrldpUri.into()],
                            )],
                        )],
                    )],
                )],
            ),
        ],
    );

    let authority_info_access = LabelObject::new(
        Some(CertExtAia.into()),
        vec![
            CertExtAiaOid.into(),
            LabelObject::new(
                Some(CertExtAiaValue.into()),
                vec![LabelObject::new(
                    Some(CertExtAiaSeq.into()),
                    vec![LabelObject::new(
                        Some(CertExtAiaAccessDescription.into()),
                        vec![
                            CertExtAiaCaIssuersOid.into(),
                            CertExtAiaCaIssuersUri.into(),
                        ],
                    )],
                )],
            ),
        ],
    );

    let subject_info_access_seq = LabelObject {
        label: Some(CertExtSiaSeq.into()),
        children: vec![],
        label_function: Some(label_fn_extension_subject_info_access_seq),
    };
    let subject_info_access = LabelObject::new(
        Some(CertExtSia.into()),
        vec![
            CertExtSiaOid.into(),
            LabelObject::new(Some(CertExtSiaValue.into()), vec![subject_info_access_seq]),
        ],
    );

    let certificate_policies = LabelObject::new(
        Some(CertExtCp.into()),
        vec![
            CertExtCpOid.into(),
            CertExtCpCritc.into(),
            LabelObject::new(
                Some(CertExtCpValue.into()),
                vec![LabelObject::new(
                    Some(CertExtCpSeq.into()),
                    vec![LabelObject::new(
                        Some(CertExtCpPolicyInformation.into()),
                        vec![
                            CertExtCpPolicyIdentifierOid.into(),
                            // TODO check if this is the correct labelling
                            LabelObject::new(
                            Some(CertExtCpPolicyQualifiers.into()),
                            vec![
                                LabelObject::new(
                                    Some(CertExtCpPolicyQualifierInfo.into()),
                                    vec![
                                        CertExtCpPolicyQualifierOid.into(),
                                        CertExtCpPolicyQualifier.into(),
                                    ]
                                )
                            ],
                        )],
                    )],
                )],
            ),
        ],
    );

    // let ip_addr_blocks = LabelObject::new(
    //     Some("ipAddrBlocksExt".to_string()),
    //     vec![
    //         LabelObject::new(Some("ipAddrBlocksExtID".to_string()), vec![]),
    //         LabelObject::new(Some("ipAddrBlocksCritc".to_string()), vec![]),
    //         LabelObject::new(
    //             Some("ipAddrBlocksOctetString".to_string()),
    //             vec![LabelObject::new(
    //                 Some("ipAddrBlocksSequence".to_string()),
    //                 vec![LabelObject::new(
    //                     Some("ipAddrBlocksInnerSeq".to_string()),
    //                     vec![
    //                         LabelObject::new(Some("ipAddrBlockFamily".to_string()), vec![]),
    //                         LabelObject::new(
    //                             Some("ipAddrBlockDataSeq".to_string()),
    //                             vec![
    //                                 LabelObject::new(Some("ipAddrBlockMin".to_string()), vec![]),
    //                                 LabelObject::new(Some("ipAddrBlockMax".to_string()), vec![]),
    //                             ],
    //                         ),
    //                     ],
    //                 )],
    //             )],
    //         ),
    //     ],
    // );
    let ip_addr_blocks_seq = LabelObject {
        label: Some(CertExtIpSeq.into()),
        children: vec![],
        label_function: Some(label_fn_extension_ip_addr_blocks_seq),
    };
    let ip_addr_blocks = LabelObject::new(
        Some(CertExtIp.into()),
        vec![
            CertExtIpOid.into(),
            CertExtIpCritc.into(),
            LabelObject::new(Some(CertExtIpValue.into()), vec![ip_addr_blocks_seq]),
        ],
    );

    let autonomous_system_ids = LabelObject::new(
        Some(CertExtAsid.into()),
        vec![
            CertExtAsidOid.into(),
            CertExtAsidCritc.into(),
            LabelObject::new(
                Some(CertExtAsidValue.into()),
                    // TODO
                vec![CertExtAsidSeq.into()],
            ),
        ],
    );

    let crl_numbers = LabelObject::new(
        Some(CrlExtCrln.into()),
        vec![
            CrlExtCrlnOid.into(),
            // TODO check if this is the correct labelling
            CrlExtCrlnValue.into(),
        ],
    );

    let mut map = HashMap::new();

    map.insert(CertExtBcOid.oid().unwrap(), basic_constraints);
    map.insert(CertExtSkiOid.oid().unwrap(), subject_key_identifier);
    map.insert(CertExtAkiOid.oid().unwrap(), authority_key_identifier);
    map.insert(CertExtKuOid.oid().unwrap(), key_usage);
    map.insert(CertExtCrldpOid.oid().unwrap(), crl_distribution_points);
    map.insert(CertExtAiaOid.oid().unwrap(), authority_info_access);
    map.insert(CertExtSiaOid.oid().unwrap(), subject_info_access);
    map.insert(CertExtCpOid.oid().unwrap(), certificate_policies);
    map.insert(CertExtIpOid.oid().unwrap(), ip_addr_blocks);
    map.insert(CertExtAsidOid.oid().unwrap(), autonomous_system_ids);
    map.insert(CrlExtCrlnOid.oid().unwrap(), crl_numbers);

    map
}

// Assuming typ == "crl"
pub fn label_empty_crl() -> LabelObject {
    let serial = CertFldSerialNumber.into();

    let sig_alg_id = LabelObject::new(
        Some(CertFldSignature.into()),
        vec![
            CertFldSignatureAlgorithm.into(),
            CertFldSignatureParameters.into(),
        ],
    );

    let issuer = LabelObject::new(
        Some(CertFldIssuer.into()),
        vec![LabelObject::new(
            Some(CertFldIssuerRdnSet.into()),
            vec![LabelObject::new(
                Some(CertFldIssuerAttributeTypeAndValue.into()),
                vec![
                    CertFldIssuerAttributeType.into(),
                    CertFldIssuerAttributeValue.into(),
                ],
            )],
        )],
    );

    let ext = LabelObject {
        label: Some(CertFldExtensionsSeq.into()),
        children: vec![],
        label_function: Some(label_fn_extensions),
    };

    let extensions = LabelObject::new(Some(CertFldExtensions.into()), vec![ext]);
    let certificate = {
        LabelObject::new(
            Some(Certificate.into()),
            vec![
                serial,
                sig_alg_id,
                issuer,
                CertFldValidityNotBefore.into(),
                CertFldValidityNotAfter.into(),
                extensions,
            ],
        )
    };

    let cert_choices = LabelObject::new(
        Some("certificateChoices".to_string()),
        vec![
            certificate,
            LabelObject::new(
                Some("certificateSignatureAlgorithm".to_string()),
                vec![
                    LabelObject::new(Some("certificateSignatureAlgorithmOid".to_string()), vec![]),
                    LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
                ],
            ),
            LabelObject::new(Some("certificateSignature".to_string()), vec![]),
        ],
    );

    return cert_choices;
}

pub fn label_certificate(typ: &str) -> LabelObject {
    let version = LabelObject::new(
        Some(CertFldVersionSeq.into()),
        vec![
            CertFldVersion.into(),
        ]
    );

    let serial = CertFldSerialNumber.into();

    let sig_alg_id = LabelObject::new(
        Some(CertFldSignature.into()),
        vec![
            CertFldSignatureAlgorithm.into(),
            CertFldSignatureParameters.into(),
        ],
    );

    let issuer = LabelObject::new(
        Some(CertFldIssuer.into()),
        vec![LabelObject::new(
            Some(CertFldIssuerRdnSet.into()),
            vec![LabelObject::new(
                Some(CertFldIssuerAttributeTypeAndValue.into()),
                vec![
                    CertFldIssuerAttributeType.into(),
                    CertFldIssuerAttributeValue.into(),
                ],
            )],
        )],
    );

    let validity = LabelObject::new(
        Some(CertFldValidity.into()),
        vec![
            CertFldValidityNotBefore.into(),
            CertFldValidityNotAfter.into(),
        ],
    );

    let subject = LabelObject::new(
        Some(CertFldSubject.into()),
        vec![LabelObject::new(
            Some(CertFldSubjectRdnSet.into()),
            vec![LabelObject::new(
                Some(CertFldSubjectAttributeTypeAndValue.into()),
                vec![
                    CertFldSubjectAttributeType.into(),
                    CertFldSubjectAttributeValue.into(),
                ],
            )],
        )],
    );

    let subject_publickey_info = LabelObject::new(
        Some(CertFldSubjectPublicKeyInfo.into()),
        vec![
            LabelObject::new(
                Some(CertFldSubjectPublicKeyInfoAlgorithm.into()),
                vec![
                    CertFldSubjectPublicKeyInfoAlgorithmId.into(),
                    CertFldSubjectPublicKeyInfoAlgorithmParameters.into(),
                ],
            ),
            CertFldSubjectPublicKeyInfoPublicKey.into(),
        ],
    );

    let crl_entries = CrlFldEntries.into();

    let ext = LabelObject {
        label: Some(CertFldExtensionsSeq.into()),
        children: vec![],
        label_function: Some(label_fn_extensions),
    };

    let extensions = LabelObject::new(Some(CertFldExtensions.into()), vec![ext]);
    let certificate = if typ == "crl" {
        LabelObject::new(
            Some(Certificate.into()),
            vec![
                serial,
                sig_alg_id,
                issuer,
                CertFldValidityNotBefore.into(),
                CertFldValidityNotAfter.into(),
                crl_entries,
                extensions,
            ],
        )
    } else {
        LabelObject::new(
            Some(Certificate.into()),
            vec![
                version,
                serial,
                sig_alg_id,
                issuer,
                validity,
                subject,
                subject_publickey_info,
                extensions,
            ],
        )
    };

    let cert_choices = LabelObject::new(
        Some("certificateChoices".to_string()),
        vec![
            certificate,
            LabelObject::new(
                Some("certificateSignatureAlgorithm".to_string()),
                vec![
                    LabelObject::new(Some("certificateSignatureAlgorithmOid".to_string()), vec![]),
                    LabelObject::new(Some("certificateSignatureAlgorithmParameters".to_string()), vec![]),
                ],
            ),
            LabelObject::new(Some("certificateSignature".to_string()), vec![]),
        ],
    );

    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        return LabelObject::new(Some("CertificateImp".to_string()), vec![cert_choices]);
    } else {
        return cert_choices;
    }
}

pub fn label_tree_roa() -> LabelObject {
    // let ip_field = LabelObject::new(
    //     Some("ipAddrBlocksField".to_string()),
    //     vec![LabelObject::new(
    //         Some("ipAddrBlocksOutSeq".to_string()),
    //         vec![LabelObject::new(Some("ipAddrBlocks".to_string()), vec![])],
    //     )],
    // );
    LabelObject{
        label: Some("encapsulatedContent".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_roa_ip_seq),
    }
}

pub fn label_tree_manifest() -> LabelObject {
    // let manifest_number = LabelObject::new(Some("manifestNumber".to_string()), vec![]);

    // let this_update = LabelObject::new(Some("thisUpdate".to_string()), vec![]);

    // let next_update = LabelObject::new(Some("nextUpdate".to_string()), vec![]);

    // let hash_algo = LabelObject::new(Some("manifestHashAlgorithm".to_string()), vec![]);

    // let hashes_list = LabelObject::new(Some("manifestHashes".to_string()), vec![]);

    let manifest = LabelObject{
        label: Some("encapsulatedContent".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_mft),
    };
    manifest
}

pub fn label_tree_aspa() -> LabelObject {
    let version = LabelObject::new(Some("versionImp".to_string()), vec![LabelObject::new(Some("version".to_string()), vec![])]);

    let customer_asid = LabelObject::new(Some("customerASID".to_string()), vec![]);

    let provider_as_seq = LabelObject::new(Some("providerASSequence".to_string()), vec![]);

    let aspa = LabelObject::new(Some("ASProviderAttestation".to_string()), vec![version, customer_asid, provider_as_seq]);

    aspa
}

pub fn label_tree_gbr() -> LabelObject {
    let content = LabelObject::new(Some("gbrContent".to_string()), vec![]);

    content
}

pub fn label_enc_content_inner(typ: &str) -> Vec<LabelObject> {
    let mut children = Vec::new();

    if typ == "roa" {
        children.push(label_tree_roa());
    } else if typ == "mft" {
        children.push(label_tree_manifest());
    } else if typ == "asa" {
        children.push(label_tree_aspa());
    } else if typ == "gbr" {
        children.push(label_tree_gbr());
    }

    children
}

pub fn label_enc_content() -> LabelObject {
    let oc_label = LabelObject {
        label: Some("eContentOuterOctet".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_encoded_content),
    };
    LabelObject::new(
        Some("encapsulatedContentInfo".to_string()),
        vec![
            LabelObject::new(Some("eContentType".to_string()), vec![]),
            LabelObject::new(Some("eContent".to_string()), vec![oc_label]),
        ],
    )
}

pub fn label_signed_attributes_rpki() -> HashMap<&'static str, LabelObject> {
    let mut map = HashMap::new();

    let content_type = LabelObject::new(
        Some("contentType".to_string()),
        vec![
            LabelObject::new(Some("contentTypeOid".to_string()), vec![]),
            LabelObject::new(
                Some("contentTypeValueParent".to_string()),
                vec![LabelObject::new(Some("contentTypeValue".to_string()), vec![])],
            ),
        ],
    );

    let message_digest = LabelObject::new(
        Some("messageDigestType".to_string()),
        vec![
            LabelObject::new(Some("messageDigestOid".to_string()), vec![]),
            LabelObject::new(
                Some("messageDigestValueParent".to_string()),
                vec![LabelObject::new(Some("messageDigest".to_string()), vec![])],
            ),
        ],
    );

    let signing_time = LabelObject::new(Some("signingTime".to_string()), vec![]);

    let signature = LabelObject::new(Some("signedAttrsSig".to_string()), vec![]);

    map.insert("1.2.840.113549.1.9.3", content_type);
    map.insert("1.2.840.113549.1.9.4", message_digest);
    map.insert("1.2.840.113549.1.9.5", signing_time);
    map.insert("1.2.840.113549.1.9.6", signature);

    map
}

pub fn label_signer_infos() -> LabelObject {
    let version = LabelObject::new(Some("signerVersion".to_string()), vec![]);

    let sid = LabelObject::new(Some("signerIdentifier".to_string()), vec![]);

    let digest_alg = LabelObject::new(
        Some("signerDigestAlgorithmField".to_string()),
        vec![
            LabelObject::new(Some("signerDigestAlgorithm".to_string()), vec![]),
            LabelObject::new(Some("signerDigestAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let signed_attributes = LabelObject {
        label: Some("signerSignedAttributesField".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_signed_attrs),
    };

    // let signed_attributes = LabelObject::new(Some("signerSignedAttributesField".to_string()), vec![]);

    let signed_signature_algorithm = LabelObject::new(
        Some("signerSignatureAlgorithm".to_string()),
        vec![
            LabelObject::new(Some("signerSignatureAlgorithmOid".to_string()), vec![]),
            LabelObject::new(Some("signedSignatureAlgorithmParameters".to_string()), vec![]),
        ],
    );

    let signed_signature = LabelObject::new(Some("signerSignature".to_string()), vec![]);

    let signer_info = LabelObject::new(
        Some("signerInfo".to_string()),
        vec![
            version,
            sid,
            digest_alg,
            signed_attributes,
            signed_signature_algorithm,
            signed_signature,
        ],
    );

    let signer_infos = LabelObject::new(Some("signerInfos".to_string()), vec![signer_info]);

    signer_infos
}


pub fn label_rpki_info() -> LabelObject{
    LabelObject::new(Some("rpkiInfo".to_string()), vec![
        LabelObject::new(Some("serialNumber".to_string()), vec![]),
        LabelObject::new(Some("validityPeriod".to_string()), vec![
            LabelObject::new(Some("notBefore".to_string()), vec![]),
            LabelObject::new(Some("notAfter".to_string()), vec![]),
        ]),
        LabelObject::new(Some("authorityKeyIdentifier".to_string()), vec![]),
        LabelObject::new(Some("signedObjectURI".to_string()), vec![]),
    ])
}

pub fn label_iroa() -> LabelObject{
    let oc_label = LabelObject {
        label: Some("eContentOuterOctet".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_encoded_content),
    };
    LabelObject::new(
        Some("roaSeq".to_string()),
        vec![
            LabelObject::new(Some("eContentType".to_string()), vec![]),
            LabelObject::new(Some("eContent".to_string()), vec![oc_label]),
            label_rpki_info()
        ],
    )


}

pub fn label_tree(typ: &str, tree: &Tree) -> Option<LabelObject> {
    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        let signed_data = LabelObject::new(
            Some("signedData".to_string()),
            vec![
                LabelObject::new(Some("version".to_string()), vec![]),
                LabelObject::new(
                    Some("digestAlgorithmsSet".to_string()),
                    vec![LabelObject::new(
                        Some("digestAlgorithmSeq".to_string()),
                        vec![
                            LabelObject::new(Some("digestAlgorithm".to_string()), vec![]),
                            LabelObject::new(Some("digestParameters".to_string()), vec![]),
                        ],
                    )],
                ),
                label_enc_content(),
                label_certificate(typ),
                label_signer_infos(),
            ],
        );

        let content_info = LabelObject::new(
            Some("contentInfo".to_string()),
            vec![
                LabelObject::new(Some("contentType".to_string()), vec![]),
                LabelObject::new(Some("content".to_string()), vec![signed_data]),
            ],
        );

        Some(content_info)
    } else if typ == "cert" || typ == "cer" {
        Some(label_certificate(typ))
    } else if typ == "crl" {
        let crl = tree.get_data_by_id(tree.root_id).unwrap();
        let os_parsed = openssl::x509::X509Crl::from_der(&crl).unwrap();
        let rc = os_parsed.get_revoked();
        if rc.is_none() {
            Some(label_empty_crl())
        } else {
            Some(label_certificate(typ))
        }
    } else if typ == "iroa"{
        Some(label_iroa())
    }
    else {
        None
        // unimplemented!("Unknown type: {}", typ);
    }
}
