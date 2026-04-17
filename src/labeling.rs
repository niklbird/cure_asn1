//! Label an ASN.1 syntax tree. Currently only RPKI labels are supported, which includes most X.509
//! certificate extensions.

use std::collections::HashMap;
use crate::labeling::LabelName::*;
use crate::tree_parser::{Asn1ObjType, SObjType, Tree, TypeTag};
use std::collections::HashMap;

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

#[derive(Clone, Debug)]
pub struct LabelInfo {
    pub optional_child: Option<usize>,
    pub repeating_labels: bool,
}

impl LabelInfo {
    pub fn new(repeating_labels: bool) -> LabelInfo {
        LabelInfo {
            optional_child: None,
            repeating_labels,
        }
    }
}

/// The functions generate dynamic labels for fields that are not statically defined.
// #[deprecated]
// fn label_fn_encoded_content<'a>(
//     _id: usize,
//     _tree: &Tree,
//     sotyp: SObjType,
// ) -> (Label, Vec<LabelObject>) {
//     let children = label_enc_content_inner(sotyp);
//     // let c = &tree.get_node(id).unwrap().children;
//
//     // No children or not a nested octetstring -> Just return normal
//     // if c.len() == 0 || tree.get_node(c[0]).unwrap().tag != Types::OctetString {
//     return (EContentValue.into(), children);
//     // }
//
//     // let inner_oc = LabelObject::new(Some("eContentInnerOctet".to_string()), children);
//     // let outer = LabelObject::new(Some("eContentOuterOctet".to_string()), vec![inner_oc]);
//     // outer
// }

fn label_fn_enc_content_roa(_id: usize, _tree: &Tree) -> (Label, Vec<LabelObject>) {
    (EContentValue.into(), label_enc_content_inner(SObjType::Roa))
}

fn label_fn_enc_content_mft(_id: usize, _tree: &Tree) -> (Label, Vec<LabelObject>) {
    (EContentValue.into(), label_enc_content_inner(SObjType::Mft))
}

fn label_fn_enc_content_gbr(_id: usize, _tree: &Tree) -> (Label, Vec<LabelObject>) {
    (EContentValue.into(), label_enc_content_inner(SObjType::Gbr))
}

fn label_fn_enc_content_aspa(_id: usize, _tree: &Tree) -> (Label, Vec<LabelObject>) {
    (
        EContentValue.into(),
        label_enc_content_inner(SObjType::Aspa),
    )
}

fn label_fn_signed_attrs<'a>(id: usize, tree: &Tree) -> (Label, Vec<LabelObject>) {
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
            // labels.push(LabelObject::label(None, vec![])); // FIXME
        }
    }
    (SignerInfoSignedAttributes.into(), labels)
}

fn label_fn_extensions<'a>(id: usize, tree: &Tree) -> (Label, Vec<LabelObject>) {
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
            // labels.push(LabelObject::label(None, vec![])); // FIXME
        }
    }
    (CertFldExtensionsSeq.into(), labels)
}

fn label_fn_extension_subject_info_access_seq<'a>(
    id: usize,
    tree: &Tree,
) -> (Label, Vec<LabelObject>) {
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
            // labels.push(LabelObject::label(None, vec![])); // FIXME
        }
    }
    (CertExtSiaSeq.into(), labels)
}

/// Creates a dynamic [`LabelObject`] for the RFC3779 IPAddrBlocks certificate extension.
fn label_fn_extension_ip_addr_blocks_seq(id: usize, tree: &Tree) -> (Label, Vec<LabelObject>) {
    let mut labels = Vec::new();

    // IPAddrBlocks        ::= SEQUENCE OF IPAddressFamily
    let node_seq = tree.get_node(id).unwrap();

    for child_id in &node_seq.children {
        // IPAddressFamily     ::= SEQUENCE {    -- AFI & optional SAFI --
        //       addressFamily        OCTET STRING (SIZE (2..3)),
        //       ipAddressChoice      IPAddressChoice }
        let child_nod = tree.get_node(*child_id).unwrap();

        let ip_afi = child_nod.children[0];
        let ip_address_choice = child_nod.children[1];

        let afi_arr = match tree.get_node(ip_afi).unwrap().data.as_slice() {
            [a, b] => [0, 0, *a, *b],
            [a, b, c] => [0, *a, *b, *c],
            _ => panic!("invalid AFI length"), // FIXME panic
        };
        let ipv = u32::from_be_bytes(afi_arr);

        let ip_afi_l = Label::new(CertExtIpAddressFamilyId, ipv as usize).into();

        //    IPAddressChoice     ::= CHOICE {
        //       inherit              NULL, -- inherit from issuer --
        //       addressesOrRanges    SEQUENCE OF IPAddressOrRange }
        let choice_nod = tree.get_node(ip_address_choice).unwrap();
        let choice_children = match choice_nod.tag {
            TypeTag::TLV | TypeTag::Null => vec![], // FIXME
            TypeTag::Sequence => {
                let mut child_labels = vec![];

                let mut ctr_prefix = 0;
                let mut ctr_range = 0;
                for &id in choice_nod.children.iter() {
                    // IPAddressOrRange    ::= CHOICE {
                    //     addressPrefix        IPAddress,
                    //     addressRange         IPAddressRange }
                    //
                    // IPAddressRange      ::= SEQUENCE {
                    //     min                  IPAddress,
                    //     max                  IPAddress }
                    //
                    // IPAddress           ::= BIT STRING
                    let ip_address_or_ranges_mod = tree.get_node(id).unwrap();

                    match ip_address_or_ranges_mod.tag {
                        TypeTag::TLV | TypeTag::BitString => {
                            child_labels
                                .push(Label::new(CertExtIpAddressPrefix(ipv), ctr_prefix).into());
                            ctr_prefix += 1;
                        }
                        TypeTag::Sequence => {
                            child_labels.push(LabelObject::label(
                                Label::new(CertExtIpAddressRange(ipv), ctr_prefix),
                                vec![
                                    Label::new(CertExtIpAddressRangeMin(ipv), ctr_range).into(),
                                    Label::new(CertExtIpAddressRangeMax(ipv), ctr_range).into(),
                                ],
                            ));
                            ctr_range += 1;
                        }
                        _ => unreachable!(
                            "Faulty object: {}\n{:?}",
                            tree.encode_b64(),
                            ip_address_or_ranges_mod
                        ), // FIXME panic
                    }
                }

                child_labels
            }
            _ => unreachable!("Faulty object: {}\n{:?}", tree.encode_b64(), choice_nod), // FIXME panic
        };

        let ip_addr_choice_l = LabelObject::label(
            Label::new(CertExtIpAddressChoice, ipv as usize),
            choice_children,
        );

        labels.push(LabelObject::label(
            Label::new(CertExtIpAddressFamily, ipv as usize),
            vec![ip_afi_l, ip_addr_choice_l],
        ));
    }

    (CertExtIpSeq.into(), labels)
}

fn label_fn_roa_ip_seq<'a>(id: usize, tree: &Tree) -> (Label, Vec<LabelObject>) {
    let mut labels = Vec::new();

    if tree.get_node(id).unwrap().children.len() < 2 {
        return (RoaContent.into(), vec![]);
    }

    let as_id = RoaAsid.into();

    for child_id in &tree
        .get_node(tree.get_node(id).unwrap().children[1])
        .unwrap()
        .children
    {
        let child = tree.get_node(*child_id).unwrap();

        if child.children.len() != 2 {
            continue;
        }
        let ip_afi = child.children[0];

        let ip_addresses = child.children[1];
        let ipv = if tree.get_node(ip_afi).unwrap().data == vec![0, 1] {
            1
        } else {
            2
        };

        let ip_afi_l = Label::new(RoaIpAddressFamilyAfi, ipv as usize).into();

        let mut ip_counter = 0;
        let mut child_labels = vec![];

        for ip_val in &tree.get_node(ip_addresses).unwrap().children {
            let ip_node = tree.get_node(*ip_val).unwrap();
            let ip = Label::new(RoaIpAddressSeq(ipv), ip_counter);

            let mut ip_labels = vec![];

            let lab = Label::new(RoaIpAddress(ipv), ip_counter);
            let label_ml = Label::new(RoaIpAddressMl(ipv), ip_counter);

            if ip_node.children.len() == 1 {
                ip_labels.push(LabelObject::label(lab, vec![]));
            } else {
                ip_labels.push(LabelObject::label(lab, vec![]));

                ip_labels.push(LabelObject::label(label_ml, vec![]));
            }

            child_labels.push(LabelObject::label(ip, ip_labels));
            ip_counter += 1;
        }

        let la = LabelObject::label(
            Label::new(RoaIpAddressFamilyAddresses, ipv as usize),
            child_labels,
        );
        let afi_and_ips = LabelObject::label(
            Label::new(RoaIpAddressFamily, ipv as usize),
            vec![ip_afi_l, la],
        );

        labels.push(afi_and_ips);
    }

    if tree.get_node(id).unwrap().children.len() > 2{
        // FIXME Replace RoaContent with EncapsulatedContent
        (RoaContent.into(), vec![as_id, LabelObject::label(RoaIpAddrBlocks.into(), labels), label_rpki_info()])
    } else {
        (
        RoaContent.into(),
        vec![as_id, LabelObject::label(RoaIpAddrBlocks.into(), labels)],
    )
    }
}

fn label_fn_mft<'a>(id: usize, tree: &Tree) -> (Label, Vec<LabelObject>) {
    let manifest_number = MftNumber.into();
    let this_update = MftThisUpdate.into();
    let next_update = MftNextUpdate.into();
    let hash_algo = MftFileHashAlg.into();

    let last = tree.get_node(id).unwrap().children.last();
    if last.is_none() {
        // FIXME Replace MftContent with EncapsulatedContent
        return (
            MftContent.into(),
            vec![manifest_number, this_update, next_update, hash_algo],
        );
    }


    let mut val_counter = 0;
    let mut entries = vec![];
    for child_id in &tree.get_node(*last.unwrap()).unwrap().children {
        let child = tree.get_node(*child_id).unwrap();
        if child.children.len() != 2 {
            continue;
        }
        let name_label = LabelObject::label(Label::new(MftFile, val_counter), vec![]);
        let hash_label = LabelObject::label(Label::new(MftHash, val_counter), vec![]);
        let entry = LabelObject::label(
            Label::new(MftFileAndHash, val_counter),
            vec![name_label, hash_label],
        );
        entries.push(entry);
        val_counter += 1;
    }
    let hashes = LabelObject::label(MftFileList.into(), entries);

    // FIXME iRPKI
    // let enc;
    // if tree.obj_type == "imft"{
    //     let crl_entries = LabelObject::new(Some("crlEntriesField".to_string()), vec![LabelObject::new(Some("crlEntries".to_string()), vec![])]);
    //
    //     enc = LabelObject::new(Some("encapsulatedContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo, hashes, crl_entries]);
    // }
    // else{
    //     enc = LabelObject::new(Some("encapsulatedContent".to_string()), vec![manifest_number, this_update, next_update, hash_algo, hashes]);
    // }
    // enc

    (
        MftContent.into(),
        vec![manifest_number, this_update, next_update, hash_algo, hashes],
    )
}

/// A [`LabelName`] uniquely names a specific token in an ASN.1 tree of an RPKI object (certificate,
/// CMS signed object, etc.).
#[rustfmt::skip]
#[derive(Clone, Debug, PartialEq, Eq, Copy, serde::Serialize, serde::Deserialize, Hash, PartialOrd, Ord)]
pub enum LabelName {
    /// Signed Object
    SignedObjectContentInfo,
    SignedObjectContentType,
    SignedObjectContent,
    SignedObjectSignedData,

    /// Version
    SignedObjectVersion,

    /// DigestAlgortihmIdentfiers
    SignedObjectDigestAlgorithms,
    SignedObjectDigestAlgorithmIdentifier,
    SignedObjectDigestAlgorithmIdentifierId,
    SignedObjectDigestAlgorithmIdentifierParameters,

    /// Outer eContentInfo
    SignedObjectEncapContentInfo,
    /// eContentType
    EContentType,
    /// eContent
    EContent,
    /// eContent OCTET STRING
    EContentValue,

    /// Route Origin Attestation
    RoaContent,
    RoaAsid,
    RoaIpAddrBlocks,
    RoaIpAddressFamily,
    RoaIpAddressFamilyAfi,
    RoaIpAddressFamilyAddresses,
    RoaIpAddressSeq(u32),
    RoaIpAddress(u32),
    RoaIpAddressMl(u32),

    /// AS Provider Authorization
    AspaContent,
    AspaProviderAuthorization,
    AspaVersion,
    AspaVersionValue,
    AspaCustomerAsid,
    AspaProviderAsSeq,

    /// Ghostbuster Record
    GbrContent,

    /// Manifest
    MftContent,
    MftVersion,
    MftNumber,
    MftThisUpdate,
    MftNextUpdate,
    MftFileHashAlg,
    MftFileList,
    MftFileAndHash,
    MftFile,
    MftHash,

    SignedObjectCertificateSet,

    // Certificate for Certs / CertificateList for CRLs / CertificateChoices for SOs
    CertificateSeq,
    /// TBSCertificate for Certs / TBSCertList for CRLs
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
    CertExtIpAddressChoice,
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

    /// signerInfos
    SignedObjectSignerInfos,
    SignerInfo,
    SignerInfoVersion,
    SignerInfoSignerIdentifier,
    SignerInfoDigestAlgorithm,
    SignerInfoDigestAlgorithmIdentifierId,
    SignerInfoDigestAlgorithmIdentifierParameters,
    SignerInfoSignedAttributes,
    SignerInfoSignedAttributeContentType,
    SignerInfoSignedAttributeContentTypeOid,
    SignerInfoSignedAttributeContentTypeValues,
    SignerInfoSignedAttributeContentTypeAttributeValue,
    SignerInfoSignedAttributeMessageDigest,
    SignerInfoSignedAttributeMessageDigestOid,
    SignerInfoSignedAttributeMessageDigestValues,
    SignerInfoSignedAttributeMessageDigestAttributeValue,
    SignerInfoSignedAttributeSigningTime,
    SignerInfoSignedAttributeSigningTimeOid,
    SignerInfoSignedAttributeSigningTimeValues,
    SignerInfoSignedAttributeSigningTimeAttributeValue,
    SignerInfoSignedAttributeBinarySigningTime,
    SignerInfoSignedAttributeBinarySigningTimeOid,
    SignerInfoSignedAttributeBinarySigningTimeValues,
    SignerInfoSignedAttributeBinarySigningTimeAttributeValue,
    SignerInfoSignedAttributeSignature,
    SignerInfoSignedAttributeSignatureOid,
    SignerInfoSignedAttributeSignatureValues,
    SignerInfoSignedAttributeSignatureAttributeValue,

    // part of the SignerInfos or Crl structure
    SignatureAlgorithm,
    SignatureAlgorithmId,
    SignatureAlgorithmParameters,
    Signature,
}

impl LabelName {
    #[rustfmt::skip]
    pub fn short_label(&self) -> &'static str {
        use LabelName::*;
        match self {
            // Signed Object
            SignedObjectContentInfo => "contentInfo",
            SignedObjectContentType => "contentType",
            SignedObjectContent => "content",
            SignedObjectSignedData => "signedData",

            SignedObjectVersion => "version",

            SignedObjectDigestAlgorithms => "digestAlgorithms",
            SignedObjectDigestAlgorithmIdentifier => "digestAlgorithmIdentifier",
            SignedObjectDigestAlgorithmIdentifierId => "digestAlgorithmIdentifierId",
            SignedObjectDigestAlgorithmIdentifierParameters => "digestAlgorithmIdentifierParameters",

            SignedObjectEncapContentInfo => "eContentInfo",
            EContentType => "eContentType",
            EContent => "eContent",
            EContentValue => "eContentValue",

            // Route Origin Authorization
            RoaContent => "roaContent",
            RoaAsid => "roaAsId",
            RoaIpAddrBlocks => "roaIpAddrBlocks",
            RoaIpAddressFamily => "roaIpAddressFamily",
            RoaIpAddressFamilyAfi => "roaIpAddressFamilyAfi",
            RoaIpAddressFamilyAddresses => "roaAddresses",
            RoaIpAddressSeq(ipv) if *ipv == 1 => "roaIpAddressSeq_v4",
            RoaIpAddressSeq(ipv) if *ipv == 2 => "roaIpAddressSeq_v6",
            RoaIpAddressSeq(_ipv) => "roaIpAddressSeq",
            RoaIpAddress(ipv) if *ipv == 1 => "roaIpAddress_v4",
            RoaIpAddress(ipv) if *ipv == 2 => "roaIpAddress_v6",
            RoaIpAddress(_ipv) => "roaIpAddress",
            RoaIpAddressMl(ipv) if *ipv == 1 => "roaIpAddressMl_v4",
            RoaIpAddressMl(ipv) if *ipv == 2 => "roaIpAddressMl_v6",
            RoaIpAddressMl(_ipv) => "roaIpAddressMl",

            // AS Path Attestation
            AspaContent => "aspaContent",
            AspaProviderAuthorization => "aspaProviderAuthorization",
            AspaVersion => "aspaVersion",
            AspaVersionValue => "aspaVersionValue",
            AspaCustomerAsid => "aspaCustomerAsid",
            AspaProviderAsSeq => "aspaProviderAsSeq",

            // Ghostbuster Record
            GbrContent => "gbrContent",

            // Manifest
            MftContent => "mftContent",
            MftVersion => "mftVersion",
            MftNumber => "mftNumber",
            MftThisUpdate => "mftThisUpdate",
            MftNextUpdate => "mftNextUpdate",
            MftFileHashAlg => "mftFileHashAlg",
            MftFileList => "mftFileList",
            MftFileAndHash => "mftFileAndHash",
            MftFile => "mftFile",
            MftHash => "mftHash",

            SignedObjectCertificateSet => "certificateSet",

            CertificateSeq => "certificateSeq",
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
            CertExtIpAddressChoice => "ipAddressDelegationIpAddrChoice",
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

            // signerInfos
            SignedObjectSignerInfos => "signerInfos",
            SignerInfo => "signerInfo",
            SignerInfoVersion => "signerInfoVersion",
            SignerInfoSignerIdentifier => "signerInfoSignerIdentifier",
            SignerInfoDigestAlgorithm => "signerInfoDigestAlgorithm",
            SignerInfoDigestAlgorithmIdentifierId => "signerInfoDigestAlgorithmId",
            SignerInfoDigestAlgorithmIdentifierParameters => "signerInfoDigestAlgorithmParameters",
            SignerInfoSignedAttributes => "signedAttributes",
            SignerInfoSignedAttributeContentType => "signedAttrContentType",
            SignerInfoSignedAttributeContentTypeOid => "signedAttrContentTypeOid",
            SignerInfoSignedAttributeContentTypeValues => "signedAttrContentTypeValues",
            SignerInfoSignedAttributeContentTypeAttributeValue => "signedAttrContentTypeAttributeValue",
            SignerInfoSignedAttributeMessageDigest => "signedAttrMessageDigest",
            SignerInfoSignedAttributeMessageDigestOid => "signedAttrMessageDigestOid",
            SignerInfoSignedAttributeMessageDigestValues => "signedAttrMessageDigestValues",
            SignerInfoSignedAttributeMessageDigestAttributeValue => "signedAttrMessageDigestAttributeValue",
            SignerInfoSignedAttributeSigningTime => "signedAttrSigningTime",
            SignerInfoSignedAttributeSigningTimeOid => "signedAttrSigningTimeOid",
            SignerInfoSignedAttributeSigningTimeValues => "signedAttrSigningTimeValues",
            SignerInfoSignedAttributeSigningTimeAttributeValue => "signedAttrSigningTimeAttributeValue",
            SignerInfoSignedAttributeBinarySigningTime => "signedAttrBinarySigningTime",
            SignerInfoSignedAttributeBinarySigningTimeOid => "signedAttrBinarySigningTimeOid",
            SignerInfoSignedAttributeBinarySigningTimeValues => "signedAttrBinarySigningTimeValues",
            SignerInfoSignedAttributeBinarySigningTimeAttributeValue => "signedAttrBinarySigningTimeAttributeValue",
            SignerInfoSignedAttributeSignature => "signedAttrSignature",
            SignerInfoSignedAttributeSignatureOid => "signedAttrSignatureOid",
            SignerInfoSignedAttributeSignatureValues => "signedAttrSignatureValues",
            SignerInfoSignedAttributeSignatureAttributeValue => "signedAttrSignatureAttributeValue",

            //
            SignatureAlgorithm => "signatureAlgorithm",
            SignatureAlgorithmId => "signatureAlgorithmId",
            SignatureAlgorithmParameters => "signatureAlgorithmParameters",
            Signature => "signature",
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
            SignerInfoSignedAttributeContentTypeOid => Some("1.2.840.113549.1.9.3"),
            SignerInfoSignedAttributeMessageDigestOid => Some("1.2.840.113549.1.9.4"),
            SignerInfoSignedAttributeSigningTimeOid => Some("1.2.840.113549.1.9.5"),
            SignerInfoSignedAttributeBinarySigningTimeOid => Some("1.2.840.113549.1.9.16.2.46"),
            SignerInfoSignedAttributeSignatureOid => Some("1.2.840.113549.1.9.6"),
            _ => None,
        }
    }
}

/// Uniquely identifies a node in the ASN.1 tree.
///
/// A label consists of a [`LabelName`], which is uniquely derived from the ASN.1 object
/// specification(s) and an index to differentiate nodes of the same name.
#[derive(
    Clone, Debug, PartialEq, Eq, Copy, serde::Serialize, serde::Deserialize, Hash, PartialOrd, Ord,
)]
pub struct Label {
    pub name: LabelName,
    pub index: usize,
}

impl Label {
    pub fn new(name: LabelName, index: usize) -> Self {
        Self { name, index }
    }

    pub(crate) fn is_ipv4(&self) -> bool {
        match self.name {
            RoaIpAddress(ipv)
            | CertExtIpAddressPrefix(ipv)
            | CertExtIpAddressRangeMin(ipv)
            | CertExtIpAddressRangeMax(ipv) => ipv == 1,
            _ => false,
        }
    }

    pub(crate) fn is_ipv6(&self) -> bool {
        match self.name {
            RoaIpAddress(ipv)
            | CertExtIpAddressPrefix(ipv)
            | CertExtIpAddressRangeMin(ipv)
            | CertExtIpAddressRangeMax(ipv) => ipv == 2,
            _ => false,
        }
    }

    pub(crate) fn is_signature(&self) -> bool {
        match self.name {
            Signature => true,
            _ => false,
        }
    }
}

impl From<LabelName> for Label {
    fn from(name: LabelName) -> Label {
        Label { name, index: 0 }
    }
}

// pub struct LabelObject {
//     pub label: Option<Label>,
//     pub children: Vec<LabelObject>,
//     pub label_function: Option<fn(usize, &Tree) -> LabelObject>,
// }

/// A [`LabelObject`] represents a derived, named node of the ASN.1 tree.
///
/// There are two possible expressions of a [`LabelObject`]:
/// - [`Label`](LabelObject::Label): A named node with defined child nodes.
/// - [`Function`](`LabelObject::Function): A lazily constructed node.
#[derive(Clone, Debug)]
pub enum LabelObject {
    Label {
        label: Label,
        children: Vec<LabelObject>,
    },
    Function {
        label_function: fn(usize, &Tree) -> (Label, Vec<LabelObject>),
    },
}

impl LabelObject {
    /// Constructs a new [`LabelObject`] of type [`LabelObject::Label`].
    pub fn label(label: Label, children: Vec<LabelObject>) -> LabelObject {
        LabelObject::Label { label, children }
    }

    pub fn function(label_function: fn(usize, &Tree) -> (Label, Vec<LabelObject>)) -> LabelObject {
        LabelObject::Function { label_function }
    }
}

impl From<Label> for LabelObject {
    fn from(label: Label) -> Self {
        Self::Label {
            label,
            children: vec![],
        }
    }
}

impl<'a> From<LabelName> for LabelObject {
    fn from(value: LabelName) -> Self {
        Self::from(<LabelName as Into<Label>>::into(value.into()))
    }
}

pub fn label_extension_subject_info_access() -> HashMap<&'static str, LabelObject> {
    let mut i = 0;
    let ca_repo_ext = LabelObject::label(
        Label::new(CertExtSiaAccessDescription, i),
        vec![
            CertExtSiaCaRepositoryOid.into(),
            CertExtSiaCaRepositoryUri.into(),
        ],
    );

    i += 1;
    let manifest_uri = LabelObject::label(
        Label::new(CertExtSiaAccessDescription, i),
        vec![
            CertExtSiaRpkiManifestOid.into(),
            CertExtSiaRpkiManifestUri.into(),
        ],
    );

    i += 1;
    let notification_uri = LabelObject::label(
        Label::new(CertExtSiaAccessDescription, i),
        vec![
            CertExtSiaNotificationOid.into(),
            CertExtSiaNotificationUri.into(),
        ],
    );

    i += 1;
    let signed_object_uri = LabelObject::label(
        Label::new(CertExtSiaAccessDescription, i),
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
    let basic_constraints = LabelObject::label(
        CertExtBc.into(),
        vec![
            CertExtBcOid.into(),
            CertExtBcCritc.into(),
            LabelObject::label(
                CertExtBcValue.into(),
                vec![LabelObject::label(
                    CertExtBcSeq.into(),
                    vec![CertExtBcCa.into()],
                )],
            ),
        ],
    );

    let subject_key_identifier = LabelObject::label(
        CertExtSki.into(),
        vec![
            CertExtSkiOid.into(),
            LabelObject::label(CertExtSkiValue.into(), vec![CertExtSkiKeyIdentifier.into()]),
        ],
    );

    let authority_key_identifier = LabelObject::label(
        CertExtAki.into(),
        vec![
            CertExtAkiOid.into(),
            LabelObject::label(
                CertExtAkiValue.into(),
                vec![LabelObject::label(
                    CertExtAkiSeq.into(),
                    vec![CertExtAkiKeyIdentifier.into()],
                )],
            ),
        ],
    );

    let key_usage = LabelObject::label(
        CertExtKu.into(),
        vec![
            CertExtKuOid.into(),
            CertExtKuCritc.into(),
            LabelObject::label(CertExtKuValue.into(), vec![CertExtKuBitstring.into()]),
        ],
    );

    let crl_distribution_points = LabelObject::label(
        CertExtCrldp.into(),
        vec![
            CertExtCrldpOid.into(),
            LabelObject::label(
                CertExtCrldpValue.into(),
                vec![LabelObject::label(
                    CertExtCrldpSeq.into(),
                    vec![LabelObject::label(
                        CertExtCrldpDistributionPoint.into(),
                        vec![LabelObject::label(
                            CertExtCrldpDistributionPointName.into(),
                            vec![LabelObject::label(
                                CertExtCrldpFullName.into(),
                                // TODO allow multiple entries for FullName
                                vec![CertExtCrldpUri.into()],
                            )],
                        )],
                    )],
                )],
            ),
        ],
    );

    let authority_info_access = LabelObject::label(
        CertExtAia.into(),
        vec![
            CertExtAiaOid.into(),
            LabelObject::label(
                CertExtAiaValue.into(),
                vec![LabelObject::label(
                    CertExtAiaSeq.into(),
                    vec![LabelObject::label(
                        CertExtAiaAccessDescription.into(),
                        vec![CertExtAiaCaIssuersOid.into(), CertExtAiaCaIssuersUri.into()],
                    )],
                )],
            ),
        ],
    );

    let subject_info_access_seq = LabelObject::function(label_fn_extension_subject_info_access_seq);
    let subject_info_access = LabelObject::label(
        CertExtSia.into(),
        vec![
            CertExtSiaOid.into(),
            LabelObject::label(CertExtSiaValue.into(), vec![subject_info_access_seq]),
        ],
    );

    let certificate_policies = LabelObject::label(
        CertExtCp.into(),
        vec![
            CertExtCpOid.into(),
            CertExtCpCritc.into(),
            LabelObject::label(
                CertExtCpValue.into(),
                vec![LabelObject::label(
                    CertExtCpSeq.into(),
                    vec![LabelObject::label(
                        CertExtCpPolicyInformation.into(),
                        vec![
                            CertExtCpPolicyIdentifierOid.into(),
                            // TODO check if this is the correct labelling
                            LabelObject::label(
                                CertExtCpPolicyQualifiers.into(),
                                vec![LabelObject::label(
                                    CertExtCpPolicyQualifierInfo.into(),
                                    vec![
                                        CertExtCpPolicyQualifierOid.into(),
                                        CertExtCpPolicyQualifier.into(),
                                    ],
                                )],
                            ),
                        ],
                    )],
                )],
            ),
        ],
    );

    // let ip_addr_blocks = LabelObject::label(
    //     Some("ipAddrBlocksExt".to_string()),
    //     vec![
    //         LabelObject::label(Some("ipAddrBlocksExtID".to_string()), vec![]),
    //         LabelObject::label(Some("ipAddrBlocksCritc".to_string()), vec![]),
    //         LabelObject::label(
    //             Some("ipAddrBlocksOctetString".to_string()),
    //             vec![LabelObject::label(
    //                 Some("ipAddrBlocksSequence".to_string()),
    //                 vec![LabelObject::label(
    //                     Some("ipAddrBlocksInnerSeq".to_string()),
    //                     vec![
    //                         LabelObject::label(Some("ipAddrBlockFamily".to_string()), vec![]),
    //                         LabelObject::label(
    //                             Some("ipAddrBlockDataSeq".to_string()),
    //                             vec![
    //                                 LabelObject::label(Some("ipAddrBlockMin".to_string()), vec![]),
    //                                 LabelObject::label(Some("ipAddrBlockMax".to_string()), vec![]),
    //                             ],
    //                         ),
    //                     ],
    //                 )],
    //             )],
    //         ),
    //     ],
    // );
    let ip_addr_blocks_seq = LabelObject::function(label_fn_extension_ip_addr_blocks_seq);

    let ip_addr_blocks = LabelObject::label(
        CertExtIp.into(),
        vec![
            CertExtIpOid.into(),
            CertExtIpCritc.into(),
            LabelObject::label(CertExtIpValue.into(), vec![ip_addr_blocks_seq]),
        ],
    );

    let autonomous_system_ids = LabelObject::label(
        CertExtAsid.into(),
        vec![
            CertExtAsidOid.into(),
            CertExtAsidCritc.into(),
            LabelObject::label(
                CertExtAsidValue.into(),
                // TODO
                vec![CertExtAsidSeq.into()],
            ),
        ],
    );

    let crl_numbers = LabelObject::label(
        CrlExtCrln.into(),
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

    let sig_alg_id = LabelObject::label(
        CertFldSignature.into(),
        vec![
            CertFldSignatureAlgorithm.into(),
            CertFldSignatureParameters.into(),
        ],
    );

    // let issuer = LabelObject::new(
    //     Some(CertFldIssuer.into()),
    //     vec![LabelObject::new(
    //         Some(CertFldIssuerRdnSet.into()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldSet2".to_string()),
    //             vec![
    //                 CertFldIssuerAttributeType.into(),
    //                 CertFldIssuerAttributeValue.into(),
    //             ],
    //         ),
    //         LabelObject::new(
    //             Some("issuerFieldElement1".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid1".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName1".to_string()), vec![]),
    //             ],
    //         ),
    //         LabelObject::new(
    //             Some("issuerFieldElement2".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid2".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName2".to_string()), vec![]),
    //             ],
    //         )],
    //     ),
    //     LabelObject::new(
    //         Some("issuerFieldSet1".to_string()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldElement3".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid3".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName3".to_string()), vec![]),
    //             ],
    //         )]),
    //         LabelObject::new(
    //         Some("issuerFieldSet2".to_string()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldElement4".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid4".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName4".to_string()), vec![]),
    //             ],
    //         )])],
    // );

    let issuer = LabelObject::label(
        CertFldIssuer.into(),
        vec![LabelObject::label(
            CertFldIssuerRdnSet.into(),
            vec![LabelObject::label(
                CertFldIssuerAttributeTypeAndValue.into(),
                vec![
                    CertFldIssuerAttributeType.into(),
                    CertFldIssuerAttributeValue.into(),
                ],
            )],
        )],
    );

    let ext = LabelObject::function(label_fn_extensions);

    let extensions = LabelObject::label(CertFldExtensions.into(), vec![ext]);
    let certificate = {
        LabelObject::label(
            Certificate.into(),
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

    let cert_choices = LabelObject::label(
        CertificateSeq.into(),
        vec![
            certificate,
            LabelObject::label(
                SignatureAlgorithm.into(),
                vec![
                    SignatureAlgorithmId.into(),
                    SignatureAlgorithmParameters.into(),
                ],
            ),
            Signature.into(),
        ],
    );

    return cert_choices;
}

pub fn label_certificate(typ: Asn1ObjType) -> LabelObject {
    let version = LabelObject::label(CertFldVersionSeq.into(), vec![CertFldVersion.into()]);

    let serial = CertFldSerialNumber.into();

    let sig_alg_id = LabelObject::label(
        CertFldSignature.into(),
        vec![
            CertFldSignatureAlgorithm.into(),
            CertFldSignatureParameters.into(),
        ],
    );

    // let issuer = LabelObject::new(
    //     Some(CertFldIssuer.into()),
    //     vec![LabelObject::new(
    //         Some(CertFldIssuerRdnSet.into()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldSet2".to_string()),
    //             vec![
    //                 CertFldIssuerAttributeType.into(),
    //                 CertFldIssuerAttributeValue.into(),
    //             ],
    //         ),
    //         LabelObject::new(
    //             Some("issuerFieldElement1".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid1".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName1".to_string()), vec![]),
    //             ],
    //         ),
    //         LabelObject::new(
    //             Some("issuerFieldElement2".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid2".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName2".to_string()), vec![]),
    //             ],
    //         )],
    //     ),
    //     LabelObject::new(
    //         Some("issuerFieldSet1".to_string()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldElement3".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid3".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName3".to_string()), vec![]),
    //             ],
    //         )]),
    //         LabelObject::new(
    //         Some("issuerFieldSet2".to_string()),
    //         vec![LabelObject::new(
    //             Some("issuerFieldElement4".to_string()),
    //             vec![
    //                 LabelObject::new(Some("issuerOid4".to_string()), vec![]),
    //                 LabelObject::new(Some("issuerName4".to_string()), vec![]),
    //             ],
    //         )])],
    // );

    let issuer = LabelObject::label(
        CertFldIssuer.into(),
        vec![LabelObject::label(
            CertFldIssuerRdnSet.into(),
            vec![LabelObject::label(
                CertFldIssuerAttributeTypeAndValue.into(),
                vec![
                    CertFldIssuerAttributeType.into(),
                    CertFldIssuerAttributeValue.into(),
                ],
            )],
        )],
    );

    let validity = LabelObject::label(
        CertFldValidity.into(),
        vec![
            CertFldValidityNotBefore.into(),
            CertFldValidityNotAfter.into(),
        ],
    );

    // let subject = LabelObject::new(
    //     Some(CertFldSubject.into()),
    //     vec![LabelObject::new(
    //         Some(CertFldSubjectRdnSet.into()),
    //         vec![LabelObject::new(
    //             Some("subjectFieldSeq2".to_string()),
    //             vec![
    //                 CertFldSubjectAttributeType.into(),
    //                 CertFldSubjectAttributeValue.into(),
    //             ],
    //
    //         ),
    //         LabelObject::new(
    //             Some("subjectFieldSeqElement1".to_string()),
    //             vec![
    //                 LabelObject::new(Some("subjectOid1".to_string()), vec![]),
    //                 LabelObject::new(Some("subjectName1".to_string()), vec![]),
    //             ],
    //
    //         ),
    //         LabelObject::new(
    //             Some("subjectFieldSeqElement2".to_string()),
    //             vec![
    //                 LabelObject::new(Some("subjectOid2".to_string()), vec![]),
    //                 LabelObject::new(Some("subjectName2".to_string()), vec![]),
    //             ],
    //
    //         )],
    //     ),
    //     LabelObject::new(
    //         Some("subjectFieldSeq2".to_string()),
    //         vec![LabelObject::new(
    //             Some("subjectFieldSeqElement2".to_string()),
    //             vec![
    //                 LabelObject::new(Some("subjectOid2".to_string()), vec![]),
    //                 LabelObject::new(Some("subjectName2".to_string()), vec![]),
    //             ],
    //
    //         ),
    //         ],
    //     ),
    //     LabelObject::new(
    //         Some("subjectFieldSeq3".to_string()),
    //         vec![LabelObject::new(
    //             Some("subjectFieldSeqElement3".to_string()),
    //             vec![
    //                 LabelObject::new(Some("subjectOid3".to_string()), vec![]),
    //                 LabelObject::new(Some("subjectName3".to_string()), vec![]),
    //             ],
    //
    //         ),
    //         ],
    //     )],
    // );

    let subject = LabelObject::label(
        CertFldSubject.into(),
        vec![LabelObject::label(
            CertFldSubjectRdnSet.into(),
            vec![LabelObject::label(
                CertFldSubjectAttributeTypeAndValue.into(),
                vec![
                    CertFldSubjectAttributeType.into(),
                    CertFldSubjectAttributeValue.into(),
                ],
            )],
        )],
    );

    let subject_publickey_info = LabelObject::label(
        CertFldSubjectPublicKeyInfo.into(),
        vec![
            LabelObject::label(
                CertFldSubjectPublicKeyInfoAlgorithm.into(),
                vec![
                    CertFldSubjectPublicKeyInfoAlgorithmId.into(),
                    CertFldSubjectPublicKeyInfoAlgorithmParameters.into(),
                ],
            ),
            CertFldSubjectPublicKeyInfoPublicKey.into(),
        ],
    );

    let crl_entries = CrlFldEntries.into();

    let ext = LabelObject::function(label_fn_extensions);

    let extensions = LabelObject::label(CertFldExtensions.into(), vec![ext]);
    let certificate = if typ == Asn1ObjType::Crl {
        LabelObject::label(
            Certificate.into(),
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
        LabelObject::label(
            Certificate.into(),
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

    let cert_choices = LabelObject::label(
        CertificateSeq.into(),
        vec![
            certificate,
            LabelObject::label(
                SignatureAlgorithm.into(),
                vec![
                    SignatureAlgorithmId.into(),
                    SignatureAlgorithmParameters.into(),
                ],
            ),
            Signature.into(),
        ],
    );

    if typ.is_signed_obj() {
        return LabelObject::label(SignedObjectCertificateSet.into(), vec![cert_choices]);
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
    // FIXME check encapsulatedContent
    //    LabelObject{
    //         label: Some("encapsulatedContent".to_string()),
    //         label_info: None,
    //         children: vec![],
    //         label_function: Some(label_fn_roa_ip_seq),
    //     }
    LabelObject::function(label_fn_roa_ip_seq)
}

pub fn label_tree_manifest() -> LabelObject {
    // let manifest_number = LabelObject::label(Some("manifestNumber".to_string()), vec![]);

    // let this_update = LabelObject::label(Some("thisUpdate".to_string()), vec![]);

    // let next_update = LabelObject::label(Some("nextUpdate".to_string()), vec![]);

    // let hash_algo = LabelObject::label(Some("manifestHashAlgorithm".to_string()), vec![]);

    // let hashes_list = LabelObject::label(Some("manifestHashes".to_string()), vec![]);

    let manifest = LabelObject::function(label_fn_mft);
    manifest
}

pub fn label_tree_aspa() -> LabelObject {
    let version = LabelObject::label(AspaVersion.into(), vec![AspaVersionValue.into()]);

    let customer_asid = AspaCustomerAsid.into();

    let provider_as_seq = AspaProviderAsSeq.into();

    let aspa = LabelObject::label(
        AspaProviderAuthorization.into(),
        vec![version, customer_asid, provider_as_seq],
    );

    aspa
}

pub fn label_tree_gbr() -> LabelObject {
    let content = GbrContent.into();

    content
}

pub fn label_enc_content_inner(typ: SObjType) -> Vec<LabelObject> {
    let mut children = Vec::new();
    use SObjType::*;
    match typ {
        Roa | IRoa | SRoa | RRoa => children.push(label_tree_roa()),
        Mft | IMft => children.push(label_tree_manifest()),
        Aspa => children.push(label_tree_aspa()),
        Gbr => children.push(label_tree_gbr()),
    }
    children
}

pub fn label_enc_content(typ: SObjType) -> LabelObject {
    let oc_label = LabelObject::function(match typ {
        SObjType::Roa => label_fn_enc_content_roa,
        SObjType::Mft => label_fn_enc_content_mft,
        SObjType::Gbr => label_fn_enc_content_gbr,
        SObjType::Aspa => label_fn_enc_content_aspa,
    });

    LabelObject::label(
        SignedObjectEncapContentInfo.into(),
        vec![
            EContentType.into(),
            LabelObject::label(EContent.into(), vec![oc_label]),
        ],
    )
}

pub fn label_signed_attributes_rpki() -> HashMap<&'static str, LabelObject> {
    let mut map = HashMap::new();

    let content_type = LabelObject::label(
        SignerInfoSignedAttributeContentType.into(),
        vec![
            SignerInfoSignedAttributeContentTypeOid.into(),
            LabelObject::label(
                SignerInfoSignedAttributeContentTypeValues.into(),
                vec![SignerInfoSignedAttributeContentTypeAttributeValue.into()],
            ),
        ],
    );

    let message_digest = LabelObject::label(
        SignerInfoSignedAttributeMessageDigest.into(),
        vec![
            SignerInfoSignedAttributeMessageDigestOid.into(),
            LabelObject::label(
                SignerInfoSignedAttributeMessageDigestValues.into(),
                vec![SignerInfoSignedAttributeMessageDigestAttributeValue.into()],
            ),
        ],
    );

    let signing_time = SignerInfoSignedAttributeSigningTime.into();
    let binary_signing_time = SignerInfoSignedAttributeBinarySigningTime.into();

    let signature = SignerInfoSignedAttributeSignature.into();

    map.insert(
        SignerInfoSignedAttributeContentTypeOid.oid().unwrap(),
        content_type,
    );
    map.insert(
        SignerInfoSignedAttributeMessageDigestOid.oid().unwrap(),
        message_digest,
    );
    map.insert(
        SignerInfoSignedAttributeSigningTimeOid.oid().unwrap(),
        signing_time,
    );
    map.insert(
        SignerInfoSignedAttributeBinarySigningTimeOid.oid().unwrap(),
        binary_signing_time,
    );
    map.insert(
        SignerInfoSignedAttributeSignatureOid.oid().unwrap(),
        signature,
    );

    map
}

pub fn label_signer_infos() -> LabelObject {
    let version = SignerInfoVersion.into();

    let sid = SignerInfoSignerIdentifier.into();

    let digest_alg = LabelObject::label(
        SignerInfoDigestAlgorithm.into(),
        vec![
            SignerInfoDigestAlgorithmIdentifierId.into(),
            SignerInfoDigestAlgorithmIdentifierParameters.into(),
        ],
    );

    let signed_attributes = LabelObject::function(label_fn_signed_attrs);

    let signed_signature_algorithm = LabelObject::label(
        SignatureAlgorithm.into(),
        vec![
            SignatureAlgorithmId.into(),
            SignatureAlgorithmParameters.into(),
        ],
    );

    let signed_signature = Signature.into();

    let signer_info = LabelObject::label(
        SignerInfo.into(),
        vec![
            version,
            sid,
            digest_alg,
            signed_attributes,
            signed_signature_algorithm,
            signed_signature,
        ],
    );

    let signer_infos = LabelObject::label(SignedObjectSignerInfos.into(), vec![signer_info]);

    signer_infos
}

pub fn label_rpki_info() -> LabelObject {
    // FIXME
    unimplemented!();
    LabelObject::new(Some("rpkiInfo".to_string()), vec![
        LabelObject::new(Some("serialNumber".to_string()), vec![]),
        LabelObject::new(Some("authorityKeyIdentifier".to_string()), vec![]),
        LabelObject::new(Some("validityPeriod".to_string()), vec![
            LabelObject::new(Some("notBefore".to_string()), vec![]),
            LabelObject::new(Some("notAfter".to_string()), vec![]),
        ]),
    ])
}

pub fn label_iroa() -> LabelObject {
    // FIXME
    unimplemented!();
    return LabelObject {
        label: Some("eContentOuterOctet".to_string()),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_roa_ip_seq),
    };
}

/// Construct a [`LabelObject`] instantiation of an ASN.1 Token [`Tree`].
///
/// Given an object type `typ`,
pub fn label_tree(typ: Asn1ObjType, tree: &Tree) -> Option<LabelObject> {
    use Asn1ObjType::*;
    match typ {
        SignedObj(sotyp) => {
            let signed_data = LabelObject::label(
                SignedObjectSignedData.into(),
                vec![
                    SignedObjectVersion.into(),
                    LabelObject::label(
                        SignedObjectDigestAlgorithms.into(),
                        vec![LabelObject::label(
                            SignedObjectDigestAlgorithmIdentifier.into(),
                            vec![
                                SignedObjectDigestAlgorithmIdentifierId.into(),
                                SignedObjectDigestAlgorithmIdentifierParameters.into(),
                            ],
                        )],
                    ),
                    label_enc_content(sotyp),
                    label_certificate(typ),
                    label_signer_infos(),
                ],
            );

            let content_info = LabelObject::label(
                SignedObjectContentInfo.into(),
                vec![
                    SignedObjectContentType.into(),
                    LabelObject::label(SignedObjectContent.into(), vec![signed_data]),
                ],
            );

            Some(content_info)
        }
        Cert | Tls | Crl => Some(label_certificate(typ)),
        IRoa | RRoa => Some(label_iroa()),
        IMft | SRoa => {
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
        }
    }
}
