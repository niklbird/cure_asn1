/*
Label an ASN.1 syntax tree. Currently only RPKI labels are supported, which includes most X.509 certificate extensions.
*/

use std::collections::HashMap;

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

/*
The following functions generate dynamic labels for fields that are not statically defined.
*/
fn label_fn_encoded_content<'a>(id: usize, tree: &Tree) -> LabelObject<'a> {
    let children = label_enc_content_inner(&tree.obj_type);
    let c = &tree.get_node(id).unwrap().children;

    // No children or not a nested octetstring -> Just return normal
    if c.len() == 0 || tree.get_node(c[0]).unwrap().tag != Types::OctetString {
        return LabelObject::new(Some("eContentOuterOctet"), children);
    }

    let inner_oc = LabelObject::new(Some("eContentInnerOctet"), children);
    let outer = LabelObject::new(Some("eContentOuterOctet"), vec![inner_oc]);
    outer
}

fn label_fn_signed_attrs<'a>(id: usize, tree: &Tree) -> LabelObject<'a> {
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
    LabelObject::new(Some("signerSignedAttributesField"), labels)
}

fn label_fn_extensions<'a>(id: usize, tree: &Tree) -> LabelObject<'a> {
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
    LabelObject::new(Some("extensions"), labels)
}

fn label_fn_subject_info<'a>(id: usize, tree: &Tree) -> LabelObject<'a> {
    let mut labels = Vec::new();

    let ext_map = label_extension_subject_info();

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
    LabelObject::new(Some("subjectInfoAccessSeq"), labels)
}

#[derive(Clone, Debug)]
pub struct LabelObject<'a> {
    pub label: Option<&'a str>,
    pub label_info: Option<LabelInfo>,
    pub children: Vec<LabelObject<'a>>,
    pub label_function: Option<fn(usize, &Tree) -> LabelObject<'a>>,
}

impl<'a> LabelObject<'a> {
    pub fn new(label: Option<&'a str>, children: Vec<LabelObject<'a>>) -> LabelObject<'a> {
        LabelObject {
            label,
            label_info: None,
            children,
            label_function: None,
        }
    }
}

pub fn label_extension_subject_info() -> HashMap<&'static str, LabelObject<'static>> {
    let ca_repo_ext = LabelObject::new(
        Some("basicConstraintsExt"),
        vec![
            LabelObject::new(Some("caRepositoryExtID"), vec![]),
            LabelObject::new(Some("caRepositoryURI"), vec![]),
        ],
    );

    let manifest_uri = LabelObject::new(
        Some("rpkiManifestExt"),
        vec![
            LabelObject::new(Some("rpkiManifestExtID"), vec![]),
            LabelObject::new(Some("rpkiManifestURI"), vec![]),
        ],
    );

    let notification_uri = LabelObject::new(
        Some("rpkiNotifyExt"),
        vec![
            LabelObject::new(Some("rpkiNotifyExtID"), vec![]),
            LabelObject::new(Some("rpkiNotifyURI"), vec![]),
        ],
    );

    let signed_object_uri = LabelObject::new(
        Some("signedObjectExt"),
        vec![
            LabelObject::new(Some("signedObjectExtID"), vec![]),
            LabelObject::new(Some("signedObjectURI"), vec![]),
        ],
    );

    let mut map = HashMap::new();
    map.insert("1.3.6.1.5.5.7.48.5", ca_repo_ext);
    map.insert("1.3.6.1.5.5.7.48.10", manifest_uri);
    map.insert("1.3.6.1.5.5.7.48.13", notification_uri);
    map.insert("1.3.6.1.5.5.7.48.11", signed_object_uri);

    map
}

pub fn label_extensions_rpki() -> HashMap<&'static str, LabelObject<'static>> {
    let basic_constaints = LabelObject::new(
        Some("basicConstraintsExt"),
        vec![
            LabelObject::new(Some("basicConstraintsExtID"), vec![]),
            LabelObject::new(Some("basicConstraintsCritc"), vec![]),
            LabelObject::new(
                Some("basicConstraintsOctetString"),
                vec![LabelObject::new(
                    Some("basicConstraintsSeq"),
                    vec![LabelObject::new(Some("basicConstraintsCA"), vec![])],
                )],
            ),
        ],
    );

    let subject_key_identifier = LabelObject::new(
        Some("subjectKeyIdentifierExt"),
        vec![
            LabelObject::new(Some("subjectKeyIdentifierExtID"), vec![]),
            LabelObject::new(
                Some("subjectKeyIdentifierOctetstring"),
                vec![LabelObject::new(Some("subjectKeyIdentifier"), vec![])],
            ),
        ],
    );

    let authority_key_identifier = LabelObject::new(
        Some("authorityKeyIdentifierExt"),
        vec![
            LabelObject::new(Some("authorityKeyIdentifierExtID"), vec![]),
            LabelObject::new(
                Some("authorityKeyIdentifierOctetstring"),
                vec![LabelObject::new(
                    Some("authorityKeyIdentifierSeq"),
                    vec![LabelObject::new(Some("authorityKeyIdentifier"), vec![])],
                )],
            ),
        ],
    );

    let key_usage = LabelObject::new(
        Some("keyUsageExt"),
        vec![
            LabelObject::new(Some("keyUsageExtExtID"), vec![]),
            LabelObject::new(Some("keyUsageCritc"), vec![]),
            LabelObject::new(
                Some("keyUsageOctetString"),
                vec![LabelObject::new(Some("keyUsageBitstring"), vec![])],
            ),
        ],
    );

    let crl_distribution_points = LabelObject::new(
        Some("crlDistributionPointsExt"),
        vec![
            LabelObject::new(Some("crlDistributionPointsExtID"), vec![]),
            LabelObject::new(
                Some("crlDistributionPointsOctetString"),
                vec![LabelObject::new(
                    Some("crlDistributionPointsSeq"),
                    vec![LabelObject::new(
                        Some("crlDistributionPointsSeq2"),
                        vec![LabelObject::new(
                            Some("crlDistributionPointsSeq3"),
                            vec![LabelObject::new(
                                Some("crlDistributionPointsSeq4"),
                                vec![LabelObject::new(Some("crlDistributionPoint"), vec![])],
                            )],
                        )],
                    )],
                )],
            ),
        ],
    );

    let authority_info_access = LabelObject::new(
        Some("authorityInfoAccessExt"),
        vec![
            LabelObject::new(Some("authorityInfoAccessExtID"), vec![]),
            LabelObject::new(
                Some("authorityInfoAccessOctetString"),
                vec![LabelObject::new(
                    Some("authorityInfoAccessSeq"),
                    vec![LabelObject::new(
                        Some("authorityInfoAccessSeq2"),
                        vec![
                            LabelObject::new(Some("caIssuersOID"), vec![]),
                            LabelObject::new(Some("caIssuersURI"), vec![]),
                        ],
                    )],
                )],
            ),
        ],
    );

    let subject_info_acc_seq = LabelObject {
        label: Some("subjectInfoAccessSeq"),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_subject_info),
    };

    let subject_info_access = LabelObject::new(
        Some("subjectInfoAccessExt"),
        vec![
            LabelObject::new(Some("subjectInfoAccessExtID"), vec![]),
            LabelObject::new(Some("subjectInfoAccessOctetString"), vec![subject_info_acc_seq]),
        ],
    );

    let certificate_policies = LabelObject::new(
        Some("certificatePoliciesExt"),
        vec![
            LabelObject::new(Some("certificatePoliciesExtID"), vec![]),
            LabelObject::new(Some("certificatePoliciesCritc"), vec![]),
            LabelObject::new(
                Some("certificatePoliciesOctetString"),
                vec![LabelObject::new(
                    Some("certificatePoliciesSeq"),
                    vec![LabelObject::new(
                        Some("certificatePoliciesSeq2"),
                        vec![LabelObject::new(
                            Some("certificatePolicyOID"),
                            vec![
                                LabelObject::new(Some("certificatePolicyQualifier"), vec![]),
                                LabelObject::new(Some("certificatePolicy"), vec![]),
                            ],
                        )],
                    )],
                )],
            ),
        ],
    );

    let ip_addr_blocks = LabelObject::new(
        Some("ipAddrBlocksExt"),
        vec![
            LabelObject::new(Some("ipAddrBlocksExtID"), vec![]),
            LabelObject::new(Some("ipAddrBlocksCritc"), vec![]),
            LabelObject::new(
                Some("ipAddrBlocksOctetString"),
                vec![LabelObject::new(
                    Some("ipAddrBlocksSequence"),
                    vec![LabelObject::new(
                        Some("ipAddrBlocksInnerSeq"),
                        vec![
                            LabelObject::new(Some("ipAddrBlockFamily"), vec![]),
                            LabelObject::new(
                                Some("ipAddrBlockDataSeq"),
                                vec![
                                    LabelObject::new(Some("ipAddrBlockMin"), vec![]),
                                    LabelObject::new(Some("ipAddrBlockMax"), vec![]),
                                ],
                            ),
                        ],
                    )],
                )],
            ),
        ],
    );

    let autonomous_system_ids = LabelObject::new(
        Some("autonomousSystemIdsExt"),
        vec![
            LabelObject::new(Some("autonomousSystemIdsExtID"), vec![]),
            LabelObject::new(Some("autonomousSystemIdsCritc"), vec![]),
            LabelObject::new(
                Some("autonomousSystemIdsOctetString"),
                vec![LabelObject::new(Some("autonomousSystemIdsSequence"), vec![])],
            ),
        ],
    );

    let crl_numbers = LabelObject::new(
        Some("crlNumbersExt"),
        vec![
            LabelObject::new(Some("crlNumbersExtID"), vec![]),
            LabelObject::new(Some("crlNumbersOctetString"), vec![LabelObject::new(Some("crlNumber"), vec![])]),
        ],
    );

    let mut map = HashMap::new();

    map.insert("2.5.29.19", basic_constaints);
    map.insert("2.5.29.14", subject_key_identifier);
    map.insert("2.5.29.35", authority_key_identifier);
    map.insert("2.5.29.15", key_usage);
    map.insert("2.5.29.31", crl_distribution_points);
    map.insert("1.3.6.1.5.5.7.1.1", authority_info_access);
    map.insert("1.3.6.1.5.5.7.1.11", subject_info_access);
    map.insert("2.5.29.32", certificate_policies);
    map.insert("1.3.6.1.5.5.7.1.7", ip_addr_blocks);
    map.insert("1.3.6.1.5.5.7.1.8", autonomous_system_ids);
    map.insert("2.5.29.20", crl_numbers);

    map
}

pub fn label_certificate(typ: &str) -> LabelObject<'static> {
    let version = LabelObject::new(Some("versionImp"), vec![LabelObject::new(Some("version"), vec![])]);

    let serial = LabelObject::new(Some("serialNumber"), vec![]);

    let sig_alg_id = LabelObject::new(
        Some("signatureAlgorithmField"),
        vec![
            LabelObject::new(Some("certificateSignatureAlgorithm"), vec![]),
            LabelObject::new(Some("certificateSignatureAlgorithmParameters"), vec![]),
        ],
    );

    let issuer = LabelObject::new(
        Some("issuerField"),
        vec![LabelObject::new(
            Some("issuerFieldSet"),
            vec![LabelObject::new(
                Some("issuerFieldSet2"),
                vec![
                    LabelObject::new(Some("issuerOid"), vec![]),
                    LabelObject::new(Some("issuerName"), vec![]),
                ],
            )],
        )],
    );

    let validity = LabelObject::new(
        Some("validityField"),
        vec![
            LabelObject::new(Some("notBefore"), vec![]),
            LabelObject::new(Some("notAfter"), vec![]),
        ],
    );

    let subject = LabelObject::new(
        Some("subjectField"),
        vec![LabelObject::new(
            Some("subjectFieldSeq"),
            vec![LabelObject::new(
                Some("subjectFieldSeq2"),
                vec![
                    LabelObject::new(Some("subjectOid"), vec![]),
                    LabelObject::new(Some("subjectName"), vec![]),
                ],
            )],
        )],
    );

    let subject_publickey_info = LabelObject::new(
        Some("subjectPublicKeyInfoField"),
        vec![
            LabelObject::new(
                Some("subjectPublicKeyInfoFieldSeq"),
                vec![
                    LabelObject::new(Some("subjectPublicKeyAlgorithm"), vec![]),
                    LabelObject::new(Some("subjectPublicKeyAlgorithmParameters"), vec![]),
                ],
            ),
            LabelObject::new(Some("subjectPublicKey"), vec![]),
        ],
    );

    let crl_entries = LabelObject::new(Some("crlEntriesField"), vec![LabelObject::new(Some("crlEntries"), vec![])]);

    let ext = LabelObject {
        label: Some("extensions"),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_extensions),
    };

    let extensions = LabelObject::new(Some("extensionsField"), vec![ext]);
    let certificate = if typ == "crl" {
        LabelObject::new(
            Some("certificate"),
            vec![
                serial,
                sig_alg_id,
                issuer,
                LabelObject::new(Some("notBefore"), vec![]),
                LabelObject::new(Some("notAfter"), vec![]),
                crl_entries,
                extensions,
            ],
        )
    } else {
        LabelObject::new(
            Some("certificate"),
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
        Some("certificateChoices"),
        vec![
            certificate,
            LabelObject::new(
                Some("certificateSignatureAlgorithm"),
                vec![
                    LabelObject::new(Some("certificateSignatureAlgorithmOid"), vec![]),
                    LabelObject::new(Some("certificateSignatureAlgorithmParameters"), vec![]),
                ],
            ),
            LabelObject::new(Some("certificateSignature"), vec![]),
        ],
    );

    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        return LabelObject::new(Some("CertificateImp"), vec![cert_choices]);
    } else {
        return cert_choices;
    }
}

pub fn label_tree_roa() -> LabelObject<'static> {
    let ip_field = LabelObject::new(
        Some("ipAddrBlocksField"),
        vec![LabelObject::new(
            Some("ipAddrBlocksOutSeq"),
            vec![LabelObject::new(Some("ipAddrBlocks"), vec![])],
        )],
    );
    LabelObject::new(
        Some("encapsulatedContent"),
        vec![
            LabelObject::new(Some("AS-ID"), vec![]),
            LabelObject::new(Some("IpAddresses"), vec![ip_field]),
        ],
    )
}

pub fn label_tree_manifest() -> LabelObject<'static> {
    let manifest_number = LabelObject::new(Some("manifestNumber"), vec![]);

    let this_update = LabelObject::new(Some("thisUpdate"), vec![]);

    let next_update = LabelObject::new(Some("nextUpdate"), vec![]);

    let hash_algo = LabelObject::new(Some("manifestHashAlgorithm"), vec![]);

    let hashes_list = LabelObject::new(Some("manifestHashes"), vec![]);

    let manifest = LabelObject::new(
        Some("encapsulatedContent"),
        vec![manifest_number, this_update, next_update, hash_algo, hashes_list],
    );
    manifest
}

pub fn label_tree_aspa() -> LabelObject<'static> {
    let version = LabelObject::new(Some("versionImp"), vec![LabelObject::new(Some("version"), vec![])]);

    let customer_asid = LabelObject::new(Some("customerASID"), vec![]);

    let provider_as_seq = LabelObject::new(Some("providerASSequence"), vec![]);

    let aspa = LabelObject::new(Some("ASProviderAttestation"), vec![version, customer_asid, provider_as_seq]);

    aspa
}

pub fn label_tree_gbr() -> LabelObject<'static> {
    let content = LabelObject::new(Some("gbrContent"), vec![]);

    content
}

pub fn label_enc_content_inner(typ: &str) -> Vec<LabelObject<'static>> {
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

pub fn label_enc_content() -> LabelObject<'static> {
    let oc_label = LabelObject {
        label: Some("eContentOuterOctet"),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_encoded_content),
    };
    LabelObject::new(
        Some("encapsulatedContentInfo"),
        vec![
            LabelObject::new(Some("eContentType"), vec![]),
            LabelObject::new(Some("eContent"), vec![oc_label]),
        ],
    )
}

pub fn label_signed_attributes_rpki() -> HashMap<&'static str, LabelObject<'static>> {
    let mut map = HashMap::new();

    let content_type = LabelObject::new(
        Some("contentType"),
        vec![
            LabelObject::new(Some("contentTypeOid"), vec![]),
            LabelObject::new(
                Some("contentTypeValueParent"),
                vec![LabelObject::new(Some("contentTypeValue"), vec![])],
            ),
        ],
    );

    let message_digest = LabelObject::new(
        Some("messageDigestType"),
        vec![
            LabelObject::new(Some("messageDigestOid"), vec![]),
            LabelObject::new(
                Some("messageDigestValueParent"),
                vec![LabelObject::new(Some("messageDigest"), vec![])],
            ),
        ],
    );

    let signing_time = LabelObject::new(Some("signingTime"), vec![]);

    let signature = LabelObject::new(Some("signedAttrsSig"), vec![]);

    map.insert("1.2.840.113549.1.9.3", content_type);
    map.insert("1.2.840.113549.1.9.4", message_digest);
    map.insert("1.2.840.113549.1.9.5", signing_time);
    map.insert("1.2.840.113549.1.9.6", signature);

    map
}

pub fn label_signer_infos() -> LabelObject<'static> {
    let version = LabelObject::new(Some("signerVersion"), vec![]);

    let sid = LabelObject::new(Some("signerIdentifier"), vec![]);

    let digest_alg = LabelObject::new(
        Some("signerDigestAlgorithmField"),
        vec![
            LabelObject::new(Some("signerDigestAlgorithm"), vec![]),
            LabelObject::new(Some("signerDigestAlgorithmParameters"), vec![]),
        ],
    );

    let signed_attributes = LabelObject {
        label: Some("signerSignedAttributesField"),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_signed_attrs),
    };

    // let signed_attributes = LabelObject::new(Some("signerSignedAttributesField"), vec![]);

    let signed_signature_algorithm = LabelObject::new(
        Some("signerSignatureAlgorithm"),
        vec![
            LabelObject::new(Some("signerSignatureAlgorithmOid"), vec![]),
            LabelObject::new(Some("signedSignatureAlgorithmParameters"), vec![]),
        ],
    );

    let signed_signature = LabelObject::new(Some("signerSignature"), vec![]);

    let signer_info = LabelObject::new(
        Some("signerInfo"),
        vec![
            version,
            sid,
            digest_alg,
            signed_attributes,
            signed_signature_algorithm,
            signed_signature,
        ],
    );

    let signer_infos = LabelObject::new(Some("signerInfos"), vec![signer_info]);

    signer_infos
}


pub fn label_rpki_info() -> LabelObject<'static>{
    LabelObject::new(Some("rpkiInfo"), vec![
        LabelObject::new(Some("serialNumber"), vec![]),
        LabelObject::new(Some("validityPeriod"), vec![
            LabelObject::new(Some("notBefore"), vec![]),
            LabelObject::new(Some("notAfter"), vec![]),
        ]),
        LabelObject::new(Some("authorityKeyIdentifier"), vec![]),
        LabelObject::new(Some("signedObjectURI"), vec![]),
    ])
}

pub fn label_iroa() -> LabelObject<'static>{
    let oc_label = LabelObject {
        label: Some("eContentOuterOctet"),
        label_info: None,
        children: vec![],
        label_function: Some(label_fn_encoded_content),
    };
    LabelObject::new(
        Some("roaSeq"),
        vec![
            LabelObject::new(Some("eContentType"), vec![]),
            LabelObject::new(Some("eContent"), vec![oc_label]),
            label_rpki_info()
        ],
    )


}

pub fn label_tree(typ: &str) -> Option<LabelObject<'static>> {
    if typ == "roa" || typ == "mft" || typ == "gbr" || typ == "asa" {
        let signed_data = LabelObject::new(
            Some("signedData"),
            vec![
                LabelObject::new(Some("version"), vec![]),
                LabelObject::new(
                    Some("digestAlgorithmsSet"),
                    vec![LabelObject::new(
                        Some("digestAlgorithmSeq"),
                        vec![
                            LabelObject::new(Some("digestAlgorithm"), vec![]),
                            LabelObject::new(Some("digestParameters"), vec![]),
                        ],
                    )],
                ),
                label_enc_content(),
                label_certificate(typ),
                label_signer_infos(),
            ],
        );

        let content_info = LabelObject::new(
            Some("contentInfo"),
            vec![
                LabelObject::new(Some("contentType"), vec![]),
                LabelObject::new(Some("content"), vec![signed_data]),
            ],
        );

        Some(content_info)
    } else if typ == "cert" || typ == "cer" || typ == "crl" {
        Some(label_certificate(typ))
    } 
    else if typ == "iroa"{
        Some(label_iroa())
    }
    else {
        None
        // unimplemented!("Unknown type: {}", typ);
    }
}
