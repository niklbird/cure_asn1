use cure_asn1::prot;
use std::fs;

pub fn main(){
    let data = fs::read("/home/niklas/tests/c212uz1yzr5q.roa").unwrap();
    let tree = cure_asn1::rpki::parse_rpki_object(&data, &cure_asn1::rpki::ObjectType::ROA).unwrap();


    let data2 = fs::read("/home/niklas/code/x509-workspace/build/mutated_cert_0.der").unwrap();
    let tree2 = cure_asn1::rpki::parse_rpki_object(&data2, &cure_asn1::rpki::ObjectType::ROA).unwrap();

    


    let data = prot::converter::convert_to_proto(&tree);

    fs::write("/home/niklas/code/x509-workspace/build/seed_cert.pb", data).unwrap();
}