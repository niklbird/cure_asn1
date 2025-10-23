use chrono::DateTime;
use chrono::Utc;
/// Convert a DER Encoded ASN.1 X.509 Certificate into a Protofbuf equivalent
/// 
/// 
/// 
/// 

use prost::Message;
use crate::asn1_parser::encode_asn1_length;
use crate::prot::compile;
use crate::prot::converter::asn1::asn1_pdu::length::Types;
use crate::prot::converter::asn1::asn1_pdu::Pdu;
use crate::prot::converter::asn1::asn1_pdu::ValueElement;
use crate::prot::converter::asn1::asn1_universal_types::BitString;
use crate::prot::converter::asn1::asn1_universal_types::RootNode;
use crate::prot::converter::asn1::asn1_universal_types::UtcTime;
use crate::prot::converter::asn1::x509_certificate::AlgorithmIdentifierSequence;
use crate::prot::converter::asn1::x509_certificate::ExtensionSequence;
use crate::prot::converter::asn1::x509_certificate::NotAfter;
use crate::prot::converter::asn1::x509_certificate::NotBefore;
use crate::prot::converter::asn1::x509_certificate::SignatureAlgorithm;
use crate::prot::converter::asn1::x509_certificate::SignatureValue;
use crate::prot::converter::asn1::x509_certificate::SubjectPublicKey;
use crate::prot::converter::asn1::x509_certificate::SubjectPublicKeyInfo;
use crate::prot::converter::asn1::x509_certificate::TimeChoice;
use crate::prot::converter::asn1::x509_certificate::Validity;
use crate::prot::converter::asn1::x509_certificate::ValiditySequence;
use crate::prot::converter::x509_certificate::Extension;
use crate::prot::converter::asn1::asn1_universal_types::Boolean;
use crate::prot::converter::x509_certificate::RawExtension;
use crate::prot::converter::x509_certificate::Extensions;
use crate::prot::converter::asn1::asn1_universal_types::Integer;
use crate::prot::converter::x509_certificate::Name;
use crate::prot::converter::asn1::asn1_pdu::Identifier;
use crate::prot::converter::asn1::asn1_pdu::TagNumber;
use crate::prot::converter::asn1::asn1_pdu::Length;
use crate::prot::converter::asn1::asn1_pdu::Value;
use crate::prot::converter::x509_certificate::SubjectPublicKeyInfoSequence;
use prost_types::Timestamp;


use crate::rpki::RpkiObject;
use crate::tree_parser::decode_oid_to_string;
use crate::prot::converter::asn1::x509_certificate;
use crate::prot::converter::asn1::asn1_universal_types::ObjectIdentifier;
use crate::prot::converter::asn1::asn1_universal_types::OctetString;


// use prost_build;


fn create_pdu(tag: u8, content: &Vec<u8>, len: Vec<u8>) -> Pdu{
    let new_tag = match tag{
        48 | 49 => tag - 32,
        _ => tag,
    };

    let encoding = match tag{
        48 | 49 => 1, // constructed
        _ => 0, // primitive
    };
    

    let class = tag >> 6;
    let new_tag = new_tag & 0b00011111;

    Pdu{
        id: Some(Identifier{id_class: Some(class as i32), encoding: Some(encoding), tag_num: Some(TagNumber{low_tag_num: Some(new_tag as i32), high_tag_num: None})}),
        len: Some(Length{types: Some(Types::LengthOverride(len))}),
        val: Some(Value{val_array: vec![
            ValueElement{pdu: None, val_bits: Some(content.clone())}
            ]}),
    }
}

fn datetime_to_timechoice(value: &DateTime<Utc>) -> TimeChoice{
    let timestamp_nb = Timestamp{
        seconds: value.timestamp() as i64,
        nanos: value.timestamp_subsec_nanos() as i32,
    };

    let utime_nb = UtcTime{
        time_stamp: Some(timestamp_nb),
    };

    let tc_nb = TimeChoice{
        utc_time: Some(utime_nb),
        generalized_time: None,
    };

    tc_nb
}


pub fn der_bytes_to_proto(tag: u8, len: Vec<u8>, content: &Vec<u8>) -> Pdu{
    create_pdu(tag, content, len)
}

pub fn convert_to_proto(tree: &RpkiObject) -> Vec<u8> {
    let b = tree.content.encode();
    return compile::der_to_proto(&b);
    


    // Construct each protobuf sub-message systematically
    let mut x509 = x509_certificate::X509Certificate::default();
    let mut tbs = x509_certificate::TbsCertificate::default();
    let mut tbs_seq = x509_certificate::TbsCertificateSequence::default();

    // Version

    tbs_seq.version = Some(x509_certificate::Version {
        value: Some(5),
        pdu: None,
    });

    // // Serial
    tbs_seq.serial_number = Some(x509_certificate::SerialNumber {
        value: Some(Integer{val: Some(tree.get_cert_serial_raw().unwrap())}),
        pdu: None,
    });


    // Issuer
    let issuer_token = tree.content.get_node_by_label("issuerField").unwrap();
    let bits = tree.content.encode_node_content(issuer_token, true);

    
    let issuer_name = create_pdu(issuer_token.tag_u, &bits, encode_asn1_length(issuer_token.length) );
    tbs_seq.issuer = Some(Name{value: Some(issuer_name), pdu:None});

    // Subject
    let subject_token = tree.content.get_node_by_label("subjectField").unwrap();
    let bits = tree.content.encode_node_content(subject_token, true);
    let subject_name = create_pdu(issuer_token.tag_u, &bits, encode_asn1_length(subject_token.length) );
    tbs_seq.subject = Some(Name{value: Some(subject_name), pdu:None});


    // Subject Public Key Info
    let algo_id = tree.content.get_node_by_label("subjectPublicKeyAlgorithm").unwrap();
    let algo_pdu = create_pdu(algo_id.tag_u, &algo_id.data, encode_asn1_length(algo_id.length) );

    let parameters = tree.content.get_node_by_label("subjectPublicKeyAlgorithmParameters");
    let param_val = if parameters.is_some(){
        let encoded = tree.content.encode_node_content(parameters.unwrap(), true);
        if encoded.len() > 0 || true{
            Some(create_pdu(parameters.unwrap().tag_u, &encoded, encode_asn1_length(parameters.unwrap().length)))
        }
        else{
            None
        }
    }
    else{
        None
    };


    let algo_seq = AlgorithmIdentifierSequence{
        object_identifier: Some(algo_pdu),
        parameters: param_val,
    };


    let subkey = tree.content.get_raw_by_label("subjectPublicKey").unwrap();
    let bs = BitString{
        unused_bits: Some(subkey[0] as i32),
        val: Some(subkey[1..].to_vec()),
    };

    let subkey = SubjectPublicKey{
        value: Some(bs),
        pdu: None,
    };

    let seq =SubjectPublicKeyInfoSequence{
        algorithm_identifier: Some(algo_seq),
        subject_public_key: Some(subkey),
    };

    let spki = SubjectPublicKeyInfo{
        value: Some(seq),
        pdu: None,
    };

    tbs_seq.subject_public_key_info = Some(spki);

    // // Validity
    let not_bef = datetime_to_timechoice(&tree.get_cert_validity_not_before().unwrap());
    let not_aft = datetime_to_timechoice(&tree.get_cert_validity_not_after().unwrap());
    let nb = NotBefore{
        value: Some(not_bef),
        pdu: None,
    };
    let na = NotAfter{
        value: Some(not_aft),
        pdu: None,
    };

    let seq = ValiditySequence{
        not_before: Some(nb),
        not_after: Some(na),
    };
    
    tbs_seq.validity = Some(Validity{
        value: Some(seq),
        pdu: None,
    });


    // // Signature Algorithm
    let algo_id = tree.content.get_node_by_label("certificateSignatureAlgorithmOid").unwrap();
    let algo_pdu = create_pdu(algo_id.tag_u, &algo_id.data, encode_asn1_length(algo_id.length) );

    let parameters = tree.content.get_node_by_label("certificateSignatureAlgorithmParameters");
    let param_val = if parameters.is_some(){
        let encoded = tree.content.encode_node_content(parameters.unwrap(), true);
        if encoded.len() > 0 || true{
            Some(create_pdu(parameters.unwrap().tag_u, &encoded, encode_asn1_length(parameters.unwrap().length)))
        }
        else{
            None
        }
    }
    else{
        None
    };



    let id_seq = AlgorithmIdentifierSequence{
        object_identifier: Some(algo_pdu),
        parameters: param_val,
    };

    let sig_algo = SignatureAlgorithm{
        value: Some(id_seq),
        pdu: None,
    };

    tbs_seq.signature_algorithm = Some(sig_algo.clone());



    tbs_seq.extensions = Some(map_cert_extensions(tree));

    tbs.value = Some(tbs_seq);

    x509.tbs_certificate = Some(tbs);

    let sig_val = tree.content.get_node_by_label("certificateSignature").unwrap();
    let sig = SignatureValue{
        value: Some(BitString{
            unused_bits: Some(sig_val.data[0] as i32),
            val: Some(sig_val.data[1..].to_vec()),
        }),
        pdu: None,
    };

    x509.signature_value = Some(sig);
    x509.signature_algorithm = Some(sig_algo);

    let mut buffer = Vec::new();
    x509.encode(&mut buffer).unwrap();
    buffer
} 





pub fn map_tbs_certificate(tree: &RpkiObject){

}

#[derive(Debug)]
pub enum OidError {
    Empty,
    IncompleteArc,
    FirstTooLarge,
    SmallOutOfRange,
    ArcOverflow,
}

fn decode_base128_arcs(content: &Vec<u8>) -> Result<Vec<u64>, OidError> {
    if content.is_empty() { return Err(OidError::Empty); }
    let mut arcs = Vec::new();
    let mut val: u64 = 0;
    let mut have = false;

    for &b in content {
        val = (val << 7) | (b & 0x7f) as u64;
        have = true;
        if (b & 0x80) == 0 {
            arcs.push(val);
            val = 0;
            have = false;
        }
    }
    if have { return Err(OidError::IncompleteArc); }
    Ok(arcs)
}

fn decode_arc(encoded: &Vec<u8>) -> Vec<u32>{
    let first_byte = encoded[0];
    let first = first_byte / 40;
    let second = first_byte % 40;
    let mut oid = vec![first as u32, second as u32];

    // Decode the rest of the bytes
    let mut value = 0u32;

    for &byte in &encoded[1..] {
        if byte & 0x80 != 0 {
            // Continuation byte
            value = (value << 7) | (byte & 0x7F) as u32;
        } else {
            // Last byte of the component
            value = (value << 7) | byte as u32;
            oid.push(value);
            value = 0;
        }
    }

    oid

}

pub fn der_oid_content_to_proto(content: &Vec<u8>) -> Result<ObjectIdentifier, OidError> {
    let u = decode_oid_to_string(&content);
    let mut arcs = vec![];
    for part in u.split("."){
        let v = part.parse::<u32>().unwrap();
        arcs.push(v);
    }


    let arcs = decode_arc(content);

    let root = arcs.get(0).ok_or(OidError::Empty).ok().unwrap();


    // let (root_enum, small_opt, first_rest): (RootNode, Option<i32>, u32) = if n0 < 40 {
    //     (RootNode::RnVal0, Some(n0 as i32), /*a1*/ 0)
    // } else if n0 < 80 {
    //     let a1 = (n0 - 40) as i32;
    //     (RootNode::RnVal1, Some(a1), 0)
    // } else {
    //     // root=2; the *first* arc to go into subidentifier is (n0 - 80)
    //     (RootNode::RnVal2, None, (n0 - 80) as u32)
    // };

    // // Build the remaining subidentifiers
    // let mut sub = Vec::with_capacity(arcs.len()); // safe upper bound

    // if matches!(root_enum, RootNode::RnVal2) {
    //     sub.push(first_rest); // include a1 for root=2
    // }

    // // append a2.. from DER list arcs[1..]
    // for &v in arcs.iter().skip(1) {
    //     if v > u32::MAX  { return Err(OidError::ArcOverflow); }
    //     sub.push(v as u32);
    // }

    // // For root 0/1, small must be 0..=39 (enum ensures this, but validate anyway)
    // if let Some(si) = small_opt {
    //     let raw = si as i32;
    //     if !(0..=39).contains(&raw) {
    //         return Err(OidError::SmallOutOfRange);
    //     }
    // }

    // Ok(ObjectIdentifier {
    //     root: Some(root_enum as i32),
    //     small_identifier: small_opt.map(|x| x as i32),
    //     subidentifier: sub,
    // });
    let mut rest = vec![];


    let (small, start_idx) = if root == &0 {
        (Some(arcs[1] as i32), 2)
    } else if root == &1 {
        (Some(arcs[1] as i32), 2)
    } else {

        (None, 2) // Y = n0 - 80 but omitted in your schema
    };

    if let Some(si) = small {
        if si > 39 { return Err(OidError::SmallOutOfRange); }
    }

    // Remaining arcs are arcs[1..], but if root==2 you might want to
    // treat (n0 - 80) as the "second arc" logically; your schema stores
    // only *subsequent* arcs in subidentifier, so we just push arcs[1..].
    for &a in &arcs[start_idx..] {
        if a > u32::MAX { return Err(OidError::ArcOverflow); }
        rest.push(a as u32);
    }

    // There seems to be a bug in the tooling of Google? Will need to check, but for some reason I need to append the first arc in the end if there is no small identifier
    if *root > 1 {
        rest.push(arcs[1] as u32);

    }

    Ok(ObjectIdentifier {root: Some(*root as i32), small_identifier: small, subidentifier: rest })
}

pub fn map_cert_extensions(tree: &RpkiObject) -> Extensions{
    // ExtensionSequence

    let extensions = tree.get_encoded_extensions().unwrap();

    let mut proto_extensions = Vec::new();
    for extension in extensions{
        let oid = der_oid_content_to_proto(&extension.0); //ObjectIdentifier { root: None, small_identifier: None, subidentifier: extension.0 };

        let cont = OctetString{val: Some(extension.2)};

        let raw = RawExtension{
            extn_id: None,
            pdu: None,
            extn_value: Some(cont),
        };

       let ext = Extension{
            extn_id: oid.ok(),
            critical: Some(Boolean{val: Some(extension.1)}),
            raw_extension: Some(raw),
            types: None,
       };

        proto_extensions.push(ext);
    }
    let seq = ExtensionSequence{
        extension: None,
        extensions: proto_extensions.clone(),
    };

    // let seq = ExtensionSequence{
    //     extension: None,
    //     extensions: vec![],
    // };

    let ex = Extensions{
        pdu: None, 
        value: Some(seq),
    };
    
    ex
}
 




#[cfg(feature = "proto")] // if you’re gating generation; otherwise remove this line
pub mod asn1 {
    // Sibling modules inside the same parent: 
    pub mod asn1_universal_types {
        include!(concat!(env!("OUT_DIR"), "/asn1_universal_types.rs"));
    }
    pub mod x509_certificate {
        include!(concat!(env!("OUT_DIR"), "/x509_certificate.rs"));
    }
    pub mod asn1_pdu {
        include!(concat!(env!("OUT_DIR"), "/asn1_pdu.rs"));
    }
}

// pub fn compile_proto() {
//         let mut cfg = prost_build::Config::new();
//     cfg.compile_protos(&["protos/object.proto"], &["protos"])?;
// }