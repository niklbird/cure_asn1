use crate::{
    asn1_parser::{self},
    tree_parser::{self, Tree},
};

pub fn parse_tree(data: &Vec<u8>, typ: &str) -> Option<Tree> {
    let r = asn1_parser::parse_asn1_object_slim(data);
    if r.is_err() {
        println!("Error during parsing {:?}", r);
        return None;
    }
    let root = r.unwrap();
    let tree = Some(tree_parser::Tree::generate_tree(root, typ.to_string()));
    tree
}
