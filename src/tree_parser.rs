/**
 * Construct a syntax tree from a parsed ASN.1 object.
 */
use std::{
    collections::{HashMap, HashSet},
    fmt, str::from_utf8,
};

use crate::{
    asn1_parser::encode_asn1_length, labeling::{label_tree, LabelObject}, mutator::{self, Mutation}, rpki_utils::{self, byt_to_in}, tree_paths::{CertificatePaths, MFTPaths, ROAPaths}
};
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::asn1_parser::Element;
use crate::labeling::{Label, LabelName};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Copy)]
pub enum Types {
    Sequence,
    Set,
    OctetString,
    Implicit,
    TLV,
    NULL,
    BitString,
    ObjectIdentifier,
    Cont0,
    Integer,
    IA5String,
}

impl Types {
    pub fn to_type_id(&self) -> u8 {
        match self {
            Types::Sequence => int_to_hex(30),
            Types::Set => int_to_hex(31),
            Types::OctetString => int_to_hex(4),
            Types::Implicit => int_to_hex(0),
            Types::TLV => int_to_hex(0),
            Types::NULL => int_to_hex(5),
            Types::BitString => int_to_hex(3),
            Types::ObjectIdentifier => int_to_hex(6),
            Types::Cont0 => int_to_hex(80),
            Types::Integer => int_to_hex(2),
            Types::IA5String => int_to_hex(22),
        }
    }

    pub fn from_type_id(id: u8) -> Types {
        match id {
            0x30 | 0x50 => Types::Sequence,
            0x31 | 0x51 => Types::Set,
            0x4 | 0x24 => Types::OctetString,
            0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4 | 0xA5 | 0xA6 => Types::Implicit,
            _ => Types::TLV,
        }
    }
}

pub fn get_type_id(typ: Types) -> u8 {
    match typ {
        Types::Sequence => int_to_hex(30),
        Types::Set => int_to_hex(31),
        Types::OctetString => int_to_hex(4),
        Types::Implicit => int_to_hex(0),
        Types::TLV => int_to_hex(0),
        Types::NULL => int_to_hex(5),
        Types::BitString => int_to_hex(3),
        Types::ObjectIdentifier => int_to_hex(6),
        Types::Cont0 => int_to_hex(80),
        Types::Integer => int_to_hex(2),
        Types::IA5String => int_to_hex(22),
    }
}

pub fn id2type(id: u8) -> Types {
    match id {
        30 => Types::Sequence,
        31 => Types::Set,
        4 => Types::OctetString,
        0 => Types::Implicit,
        3 => Types::BitString,
        5 => Types::NULL,
        6 => Types::ObjectIdentifier,
        80 => Types::Cont0,
        _ => panic!("Error when converting id to type"),
    }
}

#[derive(Debug, Clone)]
pub struct SpecialTag {
    pub tag: u8,
    pub length: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Token {
    pub tag: Types,
    pub tag_u: u8,
    pub length: usize,
    pub data: Vec<u8>,
    pub parent: usize,
    pub children: Vec<usize>,
    pub id: usize,
    pub visual_tag: Vec<u8>,
    pub tainted: bool,
    pub visual_length: usize,
    pub info: String,
    pub manipulated: bool,
    pub manipulated_length: bool,
}

impl Token {
    pub fn is_root(self) -> bool {
        return self.id == 0;
    }

    pub fn new(tag: Types, length: usize, data: Vec<u8>, parent: usize, id: usize) -> Token {
        Token {
            tag: tag.clone(),
            length: length,
            data: data,
            parent: parent,
            children: Vec::new(),
            id: id,
            tainted: false,
            tag_u: get_type_id(tag),
            visual_length: length,
            info: String::new(),
            manipulated: false,
            manipulated_length: false,
            visual_tag: vec![get_type_id(tag)],
        }
    }

    pub fn set_length(&mut self, length: usize) {
        self.length = length;
        if !self.manipulated_length {
            self.visual_length = length;
        }
    }

    pub fn set_visual_length(&mut self, length: usize) {
        self.visual_length = length;
        self.manipulated_length = true;
        self.manipulated = true;
    }

    pub fn to_string_val(&self) -> ((u8, String, Vec<u8>), (usize, String, Vec<u8>), (String, String, Vec<u8>)){
        let tag_display = format!("{} [tag {}] ", &self.info, self.tag_u);
        let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

        let len_display = format!("({} byte)", self.length);
        let len_val = (self.length, len_display, encode_asn1_length(self.length));

        let con_display = format!("{}", hex::encode(&self.data));
        let con_val = (hex::encode(&self.data), con_display, self.data.clone());
        return (tag_val, len_val, con_val);

    }



    pub fn pretty_bitstring(&self) -> String{
        if self.info.contains("ipAddr"){
            if self.info.contains("6"){
                return format!("{} (IP {})", hex::encode(&self.data), rpki_utils::parse_ip(&self.data[1..].to_vec(), 2, self.data[0].into()));
            }
            else{
                return format!("{} (IP {})", hex::encode(&self.data), rpki_utils::parse_ip(&self.data[1..].to_vec(), 1, self.data[0].into()));
            }
        }

        if self.info.contains("signature"){
            return format!("{} (Signature)", hex::encode(&self.data));
        }

        vec_to_bin(&self.data)
    }

    pub fn to_string_pretty(&self) -> ((u8, String, Vec<u8>), (usize, String, Vec<u8>), (String, String, Vec<u8>)){ 
        match self.tag_u{
            0x30 | 0x50 => { // Sequence
                let dv = if self.tag_u == self.visual_tag[0] {
                    "SEQUENCE".to_string()
                } else {
                    format!("[tag {} (original SEQUENCE)]", self.visual_tag[0])
                };

                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("({} nodes)", self.children.len());
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("");
                let con_val = ("".to_string(), con_display, vec![]);
                return (tag_val, len_val, con_val);
            }
            0x31 | 0x51 => { // Set
                let dv = if self.tag_u == self.visual_tag[0] {
                    "SET".to_string()
                } else {
                    format!("[tag {} (original SET)]", self.visual_tag[0])
                };
                
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("({} nodes)", self.children.len());
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("");
                let con_val = ("".to_string(), con_display, vec![]);
                return (tag_val, len_val, con_val);
            }
            0x04 | 0x24 => { // Octetstring
                let dv = if self.tag_u == self.visual_tag[0] {
                    "OCTETSTRING".to_string()
                } else {
                    format!("[tag {} (original OCTETSTRING)]", self.visual_tag[0])
                };
                
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("({} byte)", self.length);
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("{}", hex::encode(&self.data));

                // If it has children -> Content will be included over children
                let val = match self.children.len() > 0{
                    true => vec![],
                    false => self.data.clone()
                };

                let con_val = (hex::encode(&val), con_display, val);
                return (tag_val, len_val, con_val);
            }
            0x06 | 0x26 => { // Oid
                let dv = if self.tag_u == self.visual_tag[0] {
                    "OBJECT IDENTIFIER".to_string()
                } else {
                    format!("[tag {} (original OBJECT IDENTIFIER)]", self.visual_tag[0])
                };
                
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("");
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("{}", decode_oid_to_string(&self.data));
                let con_val = (con_display.clone(), con_display, self.data.clone());
                return (tag_val, len_val, con_val);

            }
            0x02 | 0x22 => { // Integer
                let dv = if self.tag_u == self.visual_tag[0] {
                    "INTEGER".to_string()
                } else {
                    format!("[tag {} (original INTEGER)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);

                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("");
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("{}", byt_to_in(&self.data));
                let con_val = (con_display.clone(), con_display, self.data.clone());
                return (tag_val, len_val, con_val);

            }
            0xA0..=0xA6 => { // Implicit
                let dv = if self.tag_u == self.visual_tag[0] {
                    "[Implicit]".to_string()
                } else {
                    format!("[tag {} (original Implicit)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);

                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = format!("({} nodes)", self.children.len());
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let con_display = format!("");
                let con_val = ("".to_string(), con_display, vec![]);
                return (tag_val, len_val, con_val);
            }
            0x0E | 0x2E => { // TIME
                
                let dv = if self.tag_u == self.visual_tag[0] {
                    "TIME".to_string()
                } else {
                    format!("[tag {} (original TIME)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = "".to_string();
                let len_val = (self.length, len_display, encode_asn1_length(self.length));


                let data_dec = from_utf8(&self.data).unwrap_or_default();
                let parsed = chrono::DateTime::parse_from_rfc3339(data_dec);
                if parsed.is_err(){
                    return self.to_string_val();
                }

                let parsed = parsed.unwrap();
                let con_display = parsed.format("%Y-%m-%d %H:%M:%S").to_string();

                let con_val = (con_display.clone(), con_display, self.data.clone());

                return (tag_val, len_val, con_val);
            }
            0x17 | 0x37 => { // UTC Time
                let dv = if self.tag_u == self.visual_tag[0] {
                    "UTCTime".to_string()
                } else {
                    format!("[tag {} (original UTCTime)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = "".to_string();
                let len_val = (self.length, len_display, encode_asn1_length(self.length));


                let data_dec = from_utf8(&self.data).unwrap_or_default();
                let parsed = chrono::DateTime::parse_from_str(data_dec, "%Y-%m-%d %H:%M:%S");
                if parsed.is_err(){
                    return self.to_string_val();
                }

                let parsed = parsed.unwrap();
                let con_display = parsed.format("%Y-%m-%d %H:%M:%S").to_string();

                let con_val = (con_display.clone(), con_display, self.data.clone());

                return (tag_val, len_val, con_val);
                }
            0x18 | 0x38 => { // GeneralizedTime
                let dv = if self.tag_u == self.visual_tag[0] {
                    "GeneralizedTime".to_string()
                } else {
                    format!("[tag {} (original GeneralizedTime)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);
                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = "".to_string();
                let len_val = (self.length, len_display, encode_asn1_length(self.length));


                let data_dec = from_utf8(&self.data).unwrap_or_default();
                let parsed = chrono::DateTime::parse_from_str(&data_dec, "%Y-%m-%d %H:%M:%S");
                if parsed.is_err(){
                    return self.to_string_val();
                }

                let parsed = parsed.unwrap();
                let con_display = parsed.format("%Y-%m-%d %H:%M:%S").to_string();

                let con_val = (con_display.clone(), con_display, self.data.clone());

                return (tag_val, len_val, con_val);
            }
            0x07 | 0x27 | 0x0C | 0x2C | 0x12..=0x16 | 0x32..=0x36 | 0x19 ..=0x1E | 0x39..=0x3E => { // String
                let dv = if self.tag_u == self.visual_tag[0] {
                    "String".to_string()
                } else {
                    format!("[tag {} (original String)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);

                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());

                let len_display = self.data.len().to_string();
                let len_val = (self.length, len_display, encode_asn1_length(self.length));
                let tmp = hex::encode(&self.data);
                let data_dec = from_utf8(&self.data).unwrap_or(&tmp);

                let con_val = (data_dec.to_string(), data_dec.to_string(), self.data.clone());
                return (tag_val, len_val, con_val);
            } 
            0x03 | 0x23 => { // BIT STRING
                let dv = if self.tag_u == self.visual_tag[0] {
                    "Bit String".to_string()
                } else {
                    format!("[tag {} (original Bit String)]", self.visual_tag[0])
                };
                let tag_display = format!("{}  {} ", &self.info, dv);

                let tag_val = (self.tag_u, tag_display, self.visual_tag.clone());
                let len_display = format!("({} bits)", (self.data.len() - 1) * 8 - self.data[0] as usize);
                let len_val = (self.length, len_display, encode_asn1_length(self.length));

                let encoded = self.pretty_bitstring();
                let bs = vec_to_bin(&self.data);
                let con_val = (bs.to_string(), encoded.to_string(), self.data.clone());
                return (tag_val, len_val, con_val);
            }   
            _ => {
                return self.to_string_val();
            }
        }


    }
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Tree {
    pub tokens: HashMap<usize, Token>,
    pub cur_index: usize,
    pub obj_type: String,

    // This is only for identifying if a parsed name is issuer or subject in labeling
    pub first_name: bool,
    pub first_algoid: bool,
    pub first_rsa: bool,

    /// Map a label to an ID
    pub labels: HashMap<Label, usize>,
    pub mutations: Vec<Mutation>,
    pub additional_info: HashMap<String, Vec<u8>>,
    pub root_id: usize,
}

impl Tree {
    pub fn new(obj_type: &str) -> Tree {
        Tree {
            tokens: HashMap::new(),
            cur_index: 0,
            obj_type: obj_type.to_owned(),
            first_name: true,
            first_algoid: true,
            first_rsa: true,
            labels: HashMap::new(),
            mutations: Vec::new(),
            additional_info: HashMap::new(),
            root_id: 0,
        }
    }

    pub fn add_node(&mut self, tag: u8, content: Vec<u8>, parent: usize, label: Option<String>) -> usize {
        let new_id = self.cur_index + 1;
        let mut token = Token::new(Types::from_type_id(tag), content.len(), content, parent, new_id);
        
        token.visual_tag = vec![tag];
        token.tainted = true;

        if label.is_some(){
            self.labels.insert(label.unwrap(), new_id);
        }
        self.tokens.insert(new_id, token);
        self.tokens.get_mut(&parent).unwrap().children.push(new_id);

        self.taint_parents(new_id);

        
        self.cur_index += 1;
        self.fix_sizes(true);
        new_id
    }

    pub fn remove_taint(&mut self) {
        for t in self.tokens.values_mut() {
            t.tainted = false;
        }
    }

    pub fn mutate(&mut self) {
        mutator::mutate_tree(self, 1);
    }

    pub fn get_root(&self) -> &Token {
        self.tokens.get(&self.root_id).unwrap()
    }



    pub fn get_node(&self, id: usize) -> Option<&Token> {
        self.tokens.get(&id)
    }

    pub fn get_node_mut(&mut self, id: usize) -> Option<&mut Token> {
        self.tokens.get_mut(&id)
    }

    pub fn random_token_id(&self) -> usize {
        let mut rng = rand::thread_rng();
        let keys: Vec<usize> = self.tokens.keys().cloned().collect();
        let random_index = rng.gen_range(0..keys.len());
        keys[random_index]
    }

    /*
    This token ID selection favors TLV tokens, as they usually contain the content
    and are therefore the most interesting.
     */
    pub fn guided_token_id(&self) -> usize {
        let mut rng = rand::thread_rng();

        let random_index = rng.gen_range(0..4);

        if random_index == 0 {
            return self.random_token_id();
        } else {
            let mut list = Vec::with_capacity(self.tokens.len());
            for tok in self.tokens.keys() {
                if &self.tokens[tok].tag == &Types::TLV {
                    list.push(tok);
                }
            }

            if list.len() == 0 {
                return self.random_token_id();
            }
            let random_ind = rng.gen_range(0..list.len());
            return *list[random_ind];
        }
    }

    /*
    Select a random token, but emphasize encapContentInfo since that is interesting for RPKI objects
     */
    pub fn splice_token_id(&self) -> usize {
        let old_cure = false;
        let probs = vec![0, 0, 0, 1];

        if probs.choose(&mut rand::thread_rng()).unwrap() == &1 && !old_cure {
            return self.random_token_id();
        } else {
            if self.get_node_by_label("encapsulatedContentInfo").is_some() {
                let id = self
                    .get_node_by_label("encapsulatedContentInfo")
                    .unwrap()
                    .id;
                let ancestors = self.get_offspring_ids(id);

                if ancestors.len() == 0 {
                    return self.random_token_id();
                }
                let rnd = rand::thread_rng().gen_range(0..ancestors.len());

                return *ancestors.iter().nth(rnd).unwrap();
            } else {
                return self.random_token_id();
            }
        }
    }

    pub fn remove_child_id_in_parent(&mut self, id: usize) {
        if id == self.root_id {
            return;
        }
        if !self.tokens.contains_key(&id) {
            return;
        }
        let parent_id = self.get_parent(id);
        if !self.tokens.contains_key(&parent_id) {
            return;
        }

        let tok = self.tokens.get_mut(&parent_id).unwrap();

        let mut to_remove = vec![];
        for (c, el) in tok.clone().children.iter().enumerate() {
            if el == &id {
                to_remove.push(c);
            }
        }

        // Necessary to remove from back to front since otherwise the indices shift
        to_remove.sort();
        to_remove.reverse();

        for v in to_remove {
            tok.children.remove(v);
        }
    }

    pub fn get_child_id_in_parent(&self, id: usize) -> usize {
        let parent_id = self.get_parent(id);
        for (c, el) in self.tokens[&parent_id].children.iter().enumerate() {
            if el == &id {
                return c;
            }
        }

        // This should never happen...
        println!(
            "ERROR: ID is not a child of the parent {}, parent {}",
            id, parent_id
        );
        return 0;
    }

    pub fn get_node_path(&self, id: usize) -> Vec<usize> {
        let mut next_id = id;
        let mut ret = vec![];

        while next_id != self.root_id {
            let loc = self.get_child_id_in_parent(next_id);
            ret.push(loc);
            next_id = self.get_parent(next_id);
        }
        ret.reverse();
        ret
    }

    pub fn get_node_from_node_path(&self, path: &Vec<usize>) -> usize {
        let mut cur_id = 0;
        for p in path {
            let children = &self.get_node(cur_id).unwrap().children;
            if children.len() == 0 {
                return cur_id;
            }
            if p >= &children.len() {
                cur_id = *children.last().unwrap();
            } else {
                cur_id = children[*p];
            }
        }
        cur_id
    }

    pub fn insert_new_nodes(
        &mut self,
        node_id: usize,
        new_nodes: &HashMap<usize, Token>,
        current_index: &mut usize,
        parent_id: usize,
    ) {
        let mut tok = new_nodes.get(&node_id).unwrap().clone();
        tok.id = *current_index;
        tok.parent = parent_id;

        self.tokens.insert(*current_index, tok.clone());
        self.labels.insert(tok.info.clone(), *current_index);

        *current_index += 1;

        let mut direct_children = Vec::with_capacity(tok.children.len());
        for c in &tok.children {
            direct_children.push(*current_index);
            self.insert_new_nodes(*c, new_nodes, current_index, tok.id);
        }
        self.tokens.get_mut(&tok.id).unwrap().children = direct_children;
    }

    pub fn splice_tree(
        &mut self,
        node_id: usize,
        new_nodes: &HashMap<usize, Token>,
        new_node_id: usize,
    ) {
        let offspring = self.get_offspring_ids(node_id);
        for v in offspring {
            self.labels.remove(&self.tokens[&v].info);
            let was_smth = self.tokens.remove(&v);
            if was_smth.is_none() {
                // This should never happen..
                println!("\n\n Removing didnt work {}", v);
            }
        }

        self.labels.remove(&self.tokens.get(&node_id).unwrap().info);
        let parent = self.tokens.get_mut(&node_id).unwrap().parent;
        *self.tokens.get_mut(&node_id).unwrap() = new_nodes[&new_node_id].clone();
        self.labels
            .insert(new_nodes[&new_node_id].info.clone(), node_id);

        // Find next insertion location
        let max_key = self.tokens.keys().max().unwrap();
        let mut insertion_location = max_key + 1;

        // Need to make this first here before calling the function since the first node has a different ID than the rest
        let mut direct_children = Vec::with_capacity(new_nodes[&new_node_id].children.len());
        for child in &new_nodes[&new_node_id].children {
            direct_children.push(insertion_location);
            self.insert_new_nodes(*child, new_nodes, &mut insertion_location, node_id);
        }
        self.tokens.get_mut(&node_id).unwrap().children = direct_children;
        self.tokens.get_mut(&node_id).unwrap().parent = parent;

        self.tokens.get_mut(&node_id).unwrap().tainted = true;
        self.tokens.get_mut(&node_id).unwrap().manipulated = true;

        self.taint_children(node_id, true);
    }

    pub fn shuffle(&mut self) {
        let mut rng = rand::thread_rng();
        let mut keys: Vec<usize> = self.tokens.keys().cloned().collect();
        let prev_keys = keys.clone();
        keys.shuffle(&mut rng);

        let mut new_tokens = HashMap::new();
        for (k, el) in prev_keys.iter().enumerate() {
            let prev_id = el;
            let new_id = keys[k];

            let mut tok = self.tokens.get(&prev_id).unwrap().clone();
            // Get token that is currently at location where the token will be placed and get its children
            let prev_children = self.tokens[&new_id].children.clone();
            let prev_parent = self.tokens[&new_id].parent;

            tok.tag = Types::TLV;
            tok.tag_u = 0;
            tok.id = new_id;
            tok.children = prev_children;
            tok.parent = prev_parent;

            if new_id == 0 {
                println!("Children length {}", tok.children.len());
            }
            new_tokens.insert(new_id, tok);
        }
        self.tokens = new_tokens;
        self.fix_sizes(false);
    }

    pub fn node_manipulated_by_label(&self, label: &str) -> bool {
        let id = self.labels.get(label);

        match id {
            Some(id) => {
                if !self.tokens.contains_key(&id) {
                    return true;
                }
                return self.tokens.get(id).unwrap().manipulated;
            }
            None => {
                return true;
            }
        }
    }

    pub fn set_node_manipulated(&mut self, id: usize, manipulated: bool) {
        self.tokens.get_mut(&id).unwrap().manipulated = manipulated;
    }

    pub fn get_ancestors(&self, id: usize) -> Vec<&Token> {
        let mut ancestors = Vec::new();
        let mut cur_id = id;
        while cur_id != self.root_id {
            let anc = self.tokens.get(&cur_id).unwrap();
            cur_id = anc.parent;

            ancestors.push(self.tokens.get(&cur_id).unwrap());
        }
        ancestors
    }

    // keeps id in tree but removes all children
    pub fn deep_delete_children(&mut self, id: usize) {
        let ids = self.get_offspring_ids(id);
        for i in ids {
            self.remove_child_id_in_parent(i);

            self.labels.remove(&self.tokens[&i].info);
            self.tokens.remove(&i).unwrap();
        }
    }

    pub fn deep_delete(&mut self, id: usize) {
        let ids = self.get_offspring_ids(id);
        for i in ids {
            self.remove_child_id_in_parent(i);

            self.labels.remove(&self.tokens[&i].info);
            self.tokens.remove(&i).unwrap();
        }

        self.remove_child_id_in_parent(id);

        if self.tokens.contains_key(&id) {
            self.labels.remove(&self.tokens[&id].info);
            self.tokens.remove(&id).unwrap();
        }
    }

    pub fn get_offspring_tokens(&self, id: usize) -> HashMap<usize, Token> {
        let mut ret = HashMap::new();
        ret.insert(id, self.tokens[&id].clone());

        for child in &self.tokens[&id].children {
            let new_map = self.get_offspring_tokens(*child);
            ret.extend(new_map);
        }
        ret
    }

    pub fn get_offspring_ids(&self, id: usize) -> HashSet<usize> {
        let mut ret = HashSet::new();

        if !self.tokens.contains_key(&id) {
            return ret;
        }
        for child in &self.tokens[&id].children {
            ret.insert(*child);

            let new_ids = self.get_offspring_ids(*child);
            ret.extend(new_ids);
        }
        ret
    }

    pub fn get_parent(&self, id: usize) -> usize {
        self.get_node(id).unwrap().parent
    }

    pub fn taint_parents(&mut self, id: usize) {
        let mut cur_node = id;

        // Iterate parents and taint them
        while cur_node != self.root_id {
            let parent_id = self.get_parent(cur_node);
            self.tokens.get_mut(&parent_id).unwrap().tainted = true;
            cur_node = parent_id;
        }
    }

    pub fn taint_children(&mut self, id: usize, manipulated: bool) {
        let mut cur_node = id;

        // Iterate children and taint them
        while self.tokens.get(&cur_node).unwrap().children.len() > 0 {
            let children = self.tokens.get(&cur_node).unwrap().children.clone();
            for c in children {
                self.tokens.get_mut(&c).unwrap().tainted = true;
                if manipulated {
                    self.tokens.get_mut(&c).unwrap().manipulated = true;
                }
                cur_node = c;
            }
        }
    }

    pub fn change_node(&mut self, id: usize, new: Token) {
        self.taint_parents(id);
        self.tokens.insert(id, new);
    }

    pub fn generate_tree(obj: Element, typ: String) -> Tree {
        Tree::generate_tree_index(obj, typ, 0)
    }

    pub fn get_all_oids(&self) -> HashSet<String>{
        let mut oids = HashSet::new();
        for t in self.tokens.values(){
            if t.tag_u == 6{
                oids.insert(decode_oid_to_string(&t.data));
            }
        }
        oids
    }

    pub fn infer_type(tree: &Tree) -> String{
        let all_oids = tree.get_all_oids();

        let mut  known_oids = HashMap::new();
        known_oids.insert("1.2.840.113549.1.9.16.1.24", "roa");
        known_oids.insert("1.2.840.113549.1.9.16.1.26", "mft");
        known_oids.insert("1.2.840.113549.1.9.16.1.35", "gbr");
        known_oids.insert("1.2.840.113549.1.9.16.1.49", "asa");



        if all_oids.contains("1.2.840.113549.1.7.2"){ // SignedData
            for oid in known_oids.keys(){
                if all_oids.contains(*oid){
                    return known_oids.get(oid).unwrap().to_string();
                }
            }

            return "cms".to_string();
        }

        if all_oids.contains("2.5.29.20"){ // CRL Number Extension
            return "crl".to_string();
        }

        if tree.get_root().children.len() == 3{
            let children = tree.get_root().children.clone();
            if tree.tokens.get(&children[0]).unwrap().children.len() > 3 && tree.tokens.get(&children[2]).unwrap().tag_u == 3 && tree.tokens.get(&children[2]).unwrap().data.len() > 255{
                return "cer".to_string();
            }
        } 

        return "".to_string();
    }

    pub fn generate_tree_index(obj: Element, typ: String, start_index: usize) -> Tree {
        let mut tree = Tree::new(&typ);
        tree.cur_index = start_index;
        tree.root_id = start_index;
        tree.create_tree(obj, None);
        tree.fix_sizes(false);
        
        if typ == "".to_string(){
            tree.obj_type = Tree::infer_type(&tree);
        }
        
        if tree.obj_type != ""{
            tree.label_tree();
        }
        tree
    }


    fn create_tree(&mut self, obj: Element, parent_id: Option<usize>) -> usize {
        let parent = match parent_id {
            Some(id) => id,
            None => self.cur_index,
        };
        match obj {
            Element::Sequence(seq) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::Sequence, seq.total_len, vec![], parent, new_id);
                token.tag_u = seq.tag;

                self.cur_index += 1;

                for item in seq.value {
                    token.children.push(self.create_tree(item, Some(new_id)));
                }
                self.tokens.insert(new_id, token);

                return new_id;
            }
            Element::TLV(t) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::TLV, t.total_len, t.value, parent, new_id);
                token.tag_u = t.tag;
                token.visual_tag = vec![t.tag];

                self.cur_index += 1;

                self.tokens.insert(new_id, token);

                return new_id;
            }
            Element::Set(set) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::Set, set.total_len, vec![], parent, new_id);
                token.tag_u = set.tag;

                self.cur_index += 1;

                for item in set.value {
                    token.children.push(self.create_tree(item, Some(new_id)));
                }

                self.tokens.insert(new_id, token);

                return new_id;
            }
            Element::OctetString(o) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::OctetString, o.total_len, vec![], parent, new_id);
                token.tag_u = o.tag;

                self.cur_index += 1;

                if o.value.is_some() {
                    token
                        .children
                        .push(self.create_tree(*o.value.unwrap(), Some(new_id)));
                } else {
                    token.data = o.data;
                }
                self.tokens.insert(new_id, token);

                return new_id;
            }
            Element::Implicit(im) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::Implicit, im.total_len, vec![], parent, new_id);
                token.tag_u = im.tag;
                token.visual_tag = vec![im.tag.into()];

                self.cur_index += 1;

                for v in im.value {
                    token.children.push(self.create_tree(v, Some(new_id)));
                }

                self.tokens.insert(new_id, token);

                return new_id;
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        if self.additional_info.contains_key("havocc") {
            return self.additional_info.get("havocc").unwrap().clone();
        }
        let root = self.get_root();
        let mut data = self.encode_node(root);
        if self.additional_info.contains_key("min_size"){
            while data.len() < self.additional_info.get("min_size").unwrap()[0].into(){
                data.push(0);
            }
        }

        data
    }

    pub fn label_tree(&mut self) {
        let label_obj = label_tree(&self.obj_type, &self);

        if label_obj.is_none() {
            // Unknown Object Type -> Cant label
            return;
        }

        let label_obj = label_obj.unwrap();
        self.label_tree_rec(self.root_id, &label_obj);
    }

    pub fn label_tree_rec(&mut self, id: usize, label_obj: &LabelObject) {
        let obj;
        let lobj;

        // Some labels might need to be generated dynamically (adapted to the tree structure)
        // -> Call the label function if available to generate the labels for the current node dynamically
        if label_obj.label_function.is_some() {
            obj = label_obj.label_function.unwrap()(id, self);
            lobj = &obj;
        } else {
            lobj = label_obj;
        }

        if let Some(label) = &lobj.label {
            let label_s = label.to_string();
            self.tokens.get_mut(&id).unwrap().info = label_s.clone();
            self.labels.insert(label_s, id);
        }

        for i in 0..lobj.children.len() {
            if i < self.get_node(id).unwrap().children.len() {
                let child_id = self.get_node(id).unwrap().children[i];
                self.label_tree_rec(child_id.clone(), &lobj.children[i]);
            }
        }
    }

    /*
    Fix the ASN.1 sizes of the tree after a change to the content of an object.
    Necessary because if the length of a nested field changes, all parents need to be updated.
    @param mandatory_taint: If true, only tainted nodes will be adapted. If false, all nodes will be adapted.
     */
    pub fn fix_sizes(&mut self, mandatory_taint: bool) -> usize {
        let root_id = self.root_id;
        let (child_len_full, child_data_len) = self.fix_sizes_rec(&root_id, mandatory_taint);
        self.tokens.get_mut(&self.root_id).unwrap().set_length(child_data_len);
        return child_len_full;
    }

    pub fn fix_sizes_rec(&mut self, id: &usize, mandatory_taint: bool) -> (usize, usize) {
        let children = self.tokens.get_mut(id).unwrap().children.clone();

        let mut child_len = 0;
        for child in &children {
            // Only adapt tokens that are tainted (marked as needing to be adapted)
            if self.tokens.get(&child).unwrap().tainted || !mandatory_taint {
                let (child_len_full, child_data_len) = self.fix_sizes_rec(child, mandatory_taint);
                child_len += child_len_full;

                self.tokens
                    .get_mut(&child)
                    .unwrap()
                    .set_length(child_data_len);
            } else {
                let c = self.tokens.get(&child).unwrap().length;
                child_len += c
                    + self.tokens.get(&child).unwrap().visual_tag.len()
                    + encode_asn1_length(c).len();
            }
        }
        let own_len = self.tokens.get(&id).unwrap().data.len();
        let asn1_len = encode_asn1_length(own_len + child_len).len();

        let tag_len = self.tokens.get(&id).unwrap().visual_tag.len();

        let final_len = child_len + own_len + asn1_len + tag_len;

        return (final_len, child_len + own_len);
    }

    pub fn encode_node_content(&self, token: &Token, content: bool) -> Vec<u8> {
        let mut data = Vec::new();

        let added_len = token.visual_length as usize;

        let len_val = encode_asn1_length(added_len);

        if !content {
            data.extend_from_slice(&token.visual_tag);
            data.extend_from_slice(&len_val);
        }

        match token.tag {
            Types::Sequence => {
                if !token.data.is_empty() {
                    data.extend_from_slice(&token.data);
                }
                for id in &token.children {
                    let item = self.get_node(*id).unwrap();
                    data.extend(self.encode_node(item));
                }
                return data;
            }
            Types::TLV => {
                data.extend_from_slice(&token.data);
                for id in &token.children {
                    let item = self.get_node(*id).unwrap();
                    data.extend(self.encode_node(item));
                }
                return data;
            }
            Types::Set => {
                for id in &token.children {
                    let item = self.get_node(*id).unwrap();
                    data.extend(self.encode_node(item));
                }
                return data;
            }
            Types::OctetString => {
                if token.children.is_empty() {
                    data.extend_from_slice(&token.data);
                    return data;
                } else {
                    data.extend(self.encode_node(self.get_node(token.children[0]).unwrap()));
                }
                return data;
            }
            Types::Implicit => {
                for id in &token.children {
                    let item = self.get_node(*id).unwrap();
                    data.extend(self.encode_node(item));
                }
                return data;
            }
            Types::BitString => {
                if token.children.is_empty() {
                    data.extend(token.data.clone());
                    return data;
                } else {
                    data.extend(self.encode_node(self.get_node(token.children[0]).unwrap()));
                }
                return data;
            }
            Types::ObjectIdentifier => {
                if token.children.is_empty() {
                    data.extend(token.data.clone());
                    return data;
                } else {
                    data.extend(self.encode_node(self.get_node(token.children[0]).unwrap()));
                }
                return data;
            }
            Types::NULL => {
                data.extend(token.data.clone());
                return data;
            }
            Types::Cont0 => {
                if token.children.is_empty() {
                    data.extend(token.data.clone());
                    return data;
                } else {
                    data.extend(self.encode_node(self.get_node(token.children[0]).unwrap()));
                }
                return data;
            }
            Types::Integer => {
                data.extend(token.data.clone());
                for id in &token.children {
                    let item = self.get_node(*id).unwrap();
                    data.extend(self.encode_node(item));
                }
                return data;
            },
            Types::IA5String => {
                if token.children.is_empty() {
                    data.extend(token.data.clone());
                    return data;
                } else {
                    data.extend(self.encode_node(self.get_node(token.children[0]).unwrap()));
                }
                return data;
            },
        }
    }

    pub fn encode_node(&self, token: &Token) -> Vec<u8> {
        return self.encode_node_content(token, false);
    }

    pub fn print_id_structure_rec(&self, cur_id: usize, parents: &Vec<usize>) {
        let mut new_parents = parents.clone();
        new_parents.push(cur_id);
        for c in &self.tokens[&cur_id].children {
            self.print_id_structure_rec(*c, &new_parents);
        }
    }

    pub fn print_id_structure(&self) {
        let parents = Vec::new();
        self.print_id_structure_rec(self.root_id, &parents);
    }

    pub fn to_string(&self, node_id: usize, cur_depth: usize) -> (usize, String) {
        let space = " ".repeat(cur_depth * 2);
        let node = &self.get_node(node_id).unwrap();
        match node.tag {
            Types::Sequence => {
                let mut c = 0;
                let mut s = String::new();

                if node.children.len() > 0 {
                    for item in &node.children {
                        // Recursive handling of the sequence items, which are also `GenericObject`s.
                        let res = self.to_string(*item, cur_depth + 1);
                        c += res.0;
                        s += &res.1;
                    }
                } else {
                    let descr;
                    if node.info.is_empty() {
                        descr = node_id.to_string();
                    } else {
                        descr = node.info.clone();
                    }

                    s += &format!("{} [{}] \n", space, descr);
                    c += 1;
                }
                return (c, s);
            }
            Types::TLV => {
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }

                let mut c = 0;
                let mut s = String::new();

                if node.children.len() > 0 {
                    for item in &node.children {
                        // Recursive handling of the sequence items, which are also `GenericObject`s.
                        let res = self.to_string(*item, cur_depth + 1);
                        c += res.0;
                        s += &res.1;
                    }
                    return (c, s);
                }

                let s = format!(
                    "{} [{}] Typ{} {:?}\n",
                    space,
                    descr,
                    node.tag_u,
                    node.data
                );
                return (1, s);
            }
            Types::Set => {
                let mut c = 0;
                let mut s = String::new();

                for item in &node.children {
                    // Recursive handling of the sequence items, which are also `GenericObject`s.
                    let res = self.to_string(*item, cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                }
                return (c, s);
            }
            Types::OctetString => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ4 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::Implicit => {
                let mut c = 0;
                let mut s = String::new();
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ Imp {:?}\n", space, node_id, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::BitString => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ3 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::ObjectIdentifier => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ6 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::NULL => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ5 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::Cont0 => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ128 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            }
            Types::Integer => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ2 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            },
            Types::IA5String => {
                let mut c = 0;
                let mut s = String::new();
                let descr;
                if node.info.is_empty() {
                    descr = node_id.to_string();
                } else {
                    descr = node.info.clone();
                }
                if node.children.is_empty() {
                    s += &format!("{} [{}] Typ22 {:?}\n", space, descr, node.data);
                    return (1, s);
                } else {
                    let res = self.to_string(node.children[0], cur_depth + 1);
                    c += res.0;
                    s += &res.1;
                    return (c, s);
                }
            },
        }
    }

    pub fn get_node_by_label(&self, label: &Label) -> Option<&Token> {
        self.labels.get(label).and_then(|&id| self.get_node(id))
    }

    pub fn get_nodes_by_label_name(&self, label_name: LabelName) -> Vec<&Token> { // TODO slice?
        todo!()
    }

    pub fn get_node_by_label_mut(&mut self, label: &Label) -> Option<&mut Token> {
        let &id = self.labels.get(label)?;
        self.get_node_mut(id)
    }

    pub fn get_nodes_by_label_name_mut(&mut self, label_name: LabelName) -> Option<&mut Token> {
        todo!()
    }

    fn get_id_by_path_rec(&self, node: &Token, path: &[&str]) -> Option<usize> {
        if path.is_empty() {
            return Some(node.id);
        }
        for id in &node.children {
            let child_node = self.get_node(*id).unwrap();
            if child_node.info == path[0] {
                return self.get_id_by_path_rec(child_node, &path[1..]);
            }
        }
        None
    }

    pub fn get_id_by_path(&self, path: &[&str]) -> Option<usize> {
        if path.is_empty() {
            return None;
        }
        if path.len() == 1 {
            if path[0] == "contentInfo" {
                return Some(0);
            } else {
                return None;
            }
        }
        let root_node = self.get_root();
        for id in &root_node.children {
            let child_node = self.get_node(*id).unwrap();
            if child_node.info == path[1] {
                return self.get_id_by_path_rec(child_node, &path[2..]);
            }
        }
        None
    }

    pub fn set_data(&mut self, path: &[&str], data: &Vec<u8>, tag_type: Types) {
        let id = self.get_id_by_path(path).unwrap();
        let node = self.get_node_mut(id).unwrap();
        node.data = data.to_vec();
        node.length = data.len();
        node.visual_length = data.len();
        node.tag = tag_type.clone();
        node.tainted = true;
        node.manipulated = true;
        node.visual_tag = [get_type_id(tag_type)].to_vec();
        self.taint_parents(id);
    }

    pub fn get_data_by_label(&self, label: &str) -> Option<Vec<u8>> {
        let id = self.labels.get(label);
        match id {
            Some(id) => Some(self.encode_node(self.get_node(*id).unwrap())),
            None => None,
        }
    }

    pub fn get_data_by_id(&self, id: usize) -> Option<Vec<u8>> {
        let t = self.get_node(id);
        if t.is_none() {
            return None;
        } else {
            return Some(self.encode_node(t.unwrap()));
        }
    }

    pub fn get_raw_by_label(&self, label: &str) -> Option<Vec<u8>> {
        let id = self.labels.get(label);
        match id {
            Some(id) => Some(self.get_node(*id).unwrap().data.clone()),
            None => None,
        }
    }

    // Warning!! Setting data to a label removes the children of the node
    pub fn set_data_by_label(
        &mut self,
        label: &str,
        data: Vec<u8>,
        self_taint: bool,
        manipulated: bool,
    ) -> bool {
        let id = self.labels.get(label);
        if id.is_some() {
            let id = id.unwrap();
            self.tokens.get_mut(id).unwrap().length = data.len();
            self.tokens.get_mut(id).unwrap().visual_length = data.len();

            self.tokens.get_mut(id).unwrap().data = data;

            if self.tokens.get_mut(id).unwrap().children.len() > 0 {
                self.get_offspring_ids(*id).iter().for_each(|x| {
                    self.tokens.remove(x);
                });
                self.tokens.get_mut(id).unwrap().children = Vec::new();
            }

            // If the node is tainted, it will get its size fixed. If you manually change it choose yes
            //     If object generation inserts a manipulated field you will usually choose false
            if self_taint {
                self.tokens.get_mut(id).unwrap().tainted = true;
            }
            if manipulated {
                self.tokens.get_mut(id).unwrap().manipulated = true;
            }

            self.taint_parents(*id);
            return true;
        }
        return false;
    }

    pub fn set_element_by_label(&mut self, label: &str, element: Element, self_taint: bool, manipulated: bool) -> bool{
        let id = self.labels.get(label);
        if id.is_some() {
            let id = id.unwrap();

            // First: Remove all children of the node (They are not needed anymore)
            if self.tokens.get_mut(id).unwrap().children.len() > 0 {
                self.get_offspring_ids(*id).iter().for_each(|x| {
                    self.tokens.remove(x);
                });
            }


            let new_root = self.tokens.keys().max().unwrap_or(&0) + 1; // Insert new tokens behind existing tokens

            // Concept: Turn the new element structure into tree (token ids chosen so they dont collide with existing tree), then add the new tokens into this existing tree. 
            // To add, the interface token, i.e. the token thats added to the existing tree to connect to new tree needs to have the correct id (the id of the token its replacing).
            let tree = Tree::generate_tree_index(element, "".to_string(), new_root);

            for token in tree.tokens.values(){
                if token.id == new_root{
                    continue;
                }

                let mut new_token = token.clone();
                if new_token.parent == new_root{
                    new_token.parent = *id;
                }
                self.tokens.insert(new_token.id, new_token);
            }

            let mut replacing_token = tree.tokens[&new_root].clone();
            replacing_token.id = *id;
            replacing_token.parent = self.tokens[id].parent;
            replacing_token.manipulated = manipulated;
            replacing_token.tainted = self_taint;
            self.tokens.insert(*id, replacing_token);

            self.taint_parents(*id);
            return true;
        }
        return false;
    }

    pub fn set_visual_length_by_label(&mut self, label: &str, length: usize) -> bool {
        let id = self.labels.get(label);
        if id.is_some() {
            let id = id.unwrap();
            self.tokens.get_mut(id).unwrap().visual_length = length;
            self.tokens.get_mut(id).unwrap().manipulated_length = true;
            self.tokens.get_mut(id).unwrap().manipulated = true;
            return true;
        }
        return false;
    }

    fn print_token(&self, t: &Token, recursion: usize) {
        let children = &t.children;
        let output: String = "\t".repeat(recursion);
        println!("{} {} {} {} {} {} {} {:?}", output, t.id, t.info, t.length, t.visual_length, t.tainted, t.manipulated, t.data);
        for c in children {
            if let Some(node) = self.get_node(*c) {
                self.print_token(&node, recursion+1);
            }
        }
    }
    pub fn print_tree(&self) {
        let root = self.get_root();
        self.print_token(root, 0);
    }

    pub fn get_header_len(&self, n: &Token) -> usize {
        let data_len = n.length;
        let pid = n.parent;
        let pn = self.get_node(pid).unwrap();
        let pdata_len = pn.length;
        return pdata_len - data_len;
    }

    pub fn fix_octetstrings(&mut self, typ: &str) {
        match typ {
            "roa" => {
                let paths = ROAPaths::init();
                for p in [paths.cert_paths.ski, paths.sig_inf_paths.msg_dgst, paths.sig_inf_paths.signature] {
                    let id = self.get_id_by_path(&p).unwrap();
                    let n = self.get_node(id).unwrap();
                    let data = self.encode_node_content(n, true);
                    self.deep_delete_children(id);
                    self.set_data(&p, &data, Types::OctetString);
                }
            },
            "cer" => {
                let paths = CertificatePaths::init_cert();
                for p in [paths.ski] {
                    let id = self.get_id_by_path(&p).unwrap();
                    let n = self.get_node(id).unwrap();
                    let data = self.encode_node_content(n, true);
                    self.deep_delete_children(id);
                    self.set_data(&p, &data, Types::OctetString);
                }
            },
            "crl" => {},
            "mft" => {
                let paths = MFTPaths::init();
                for p in [paths.cert_paths.ski, paths.sig_inf_paths.msg_dgst, paths.sig_inf_paths.signature] {
                    let id = self.get_id_by_path(&p).unwrap();
                    let n = self.get_node(id).unwrap();
                    let data = self.encode_node_content(n, true);
                    self.deep_delete_children(id);
                    self.set_data(&p, &data, Types::OctetString);
                }
            },
            _ => {},
        }
    }
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string(self.root_id, 0).1)
    }
}

pub fn encode_oid(oid_str: &str) -> Result<Vec<u8>, &'static str> {
    return Ok(encode_oid_from_string(oid_str));
}

/*
OIDs are not encoded by simply encoding each . separated component as a byte.
This function implements the OID encoding logic
*/
pub fn encode_oid_from_string(oid_str: &str) -> Vec<u8> {
    let oid: Vec<u32> = oid_str
        .split('.')
        .map(|s| s.parse::<u32>().expect("Invalid OID component"))
        .collect();

    let mut encoded = Vec::new();

    // First two components are combined as 40 * X + Y
    encoded.push(40 * oid[0] as u8 + oid[1] as u8);

    for &component in &oid[2..] {
        if component < 128 {
            encoded.push(component as u8);
        } else {
            let mut stack = Vec::new();
            let mut value = component;

            while value > 0 {
                stack.push((value & 0x7F) as u8);
                value >>= 7;
            }

            while let Some(byte) = stack.pop() {
                if stack.is_empty() {
                    encoded.push(byte);
                } else {
                    encoded.push(byte | 0x80);
                }
            }
        }
    }

    encoded
}

pub fn decode_oid_to_string(encoded: &[u8]) -> String {
    if encoded.is_empty() {
        panic!("Encoded OID cannot be empty");
    }

    // Decode the first byte to get the first two components
    let first_byte = encoded[0];
    let first = first_byte / 40;
    let second = first_byte % 40;
    let mut oid = vec![first as u32, second as u32];

    // Decode the rest of the bytes
    let mut value = 0u32;
    let mut in_progress = false;

    for &byte in &encoded[1..] {
        if byte & 0x80 != 0 {
            // Continuation byte
            value = (value << 7) | (byte & 0x7F) as u32;
            in_progress = true;
        } else {
            // Last byte of the component
            value = (value << 7) | byte as u32;
            oid.push(value);
            value = 0;
            in_progress = false;
        }
    }

    // Ensure there are no incomplete components
    if in_progress {
        println!("Incomplete OID encoding");
    }

    // Convert the OID components to a dot-separated string
    oid.into_iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Converts a binary value
fn int_to_hex(v: u8) -> u8 {
    let hex_integer: u8 = u8::from_str_radix(&v.to_string(), 16).unwrap();
    hex_integer
}


fn vec_to_bin(bitstring: &Vec<u8>) -> String {
    let bitstring = &bitstring[1..];
    bitstring.iter()
        .map(|byte| format!("{:08b}", byte)) // Convert each byte to an 8-bit binary string
        .collect::<Vec<String>>() // Collect into a vector of strings
        .join("") // Join them together
}

#[cfg(test)]
mod test {
    use crate::tree_parser::int_to_hex;

    #[test]
    fn test_int_to_hex() {
        for i in 0..20 {
            println!("{}", int_to_hex(i));
        }
    }
}
