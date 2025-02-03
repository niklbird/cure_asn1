/**
 * Construct a syntax tree from a parsed ASN.1 object.
 */
use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::{
    asn1_parser::encode_asn1_length,
    labeling::{label_tree, LabelObject},
    mutator::{self, Mutation},
};
use rand::prelude::SliceRandom;
use rand::Rng;

use crate::asn1_parser::Element;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Types {
    Sequence,
    Set,
    OctetString,
    Implicit,
    TLV,
}

impl Types {
    pub fn to_type_id(&self) -> u8 {
        match self {
            Types::Sequence => int_to_hex(30),
            Types::Set => int_to_hex(31),
            Types::OctetString => int_to_hex(4),
            Types::Implicit => int_to_hex(0),
            Types::TLV => int_to_hex(0),
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
    pub length: usize,
    pub data: Vec<u8>,
    pub parent: usize,
    pub children: Vec<usize>,
    pub id: usize,
    pub imp_tag: Option<u32>,
    pub tainted: bool,
    pub visual_tag: Vec<u8>,
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
            imp_tag: None,
            tainted: false,
            visual_tag: vec![get_type_id(tag)],
            visual_length: length,
            info: String::new(),
            manipulated: false,
            manipulated_length: false,
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

    // Map a label to an ID
    pub labels: HashMap<String, usize>,
    pub mutations: Vec<Mutation>,
    pub additional_info: HashMap<String, Vec<u8>>,
}

impl Tree {
    pub fn new(obj_type: String) -> Tree {
        Tree {
            tokens: HashMap::new(),
            cur_index: 0,
            obj_type,
            first_name: true,
            first_algoid: true,
            first_rsa: true,
            labels: HashMap::new(),
            mutations: Vec::new(),
            additional_info: HashMap::new(),
        }
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
        &self.tokens.get(&0).unwrap()
    }

    pub fn get_node(&self, id: usize) -> Option<&Token> {
        self.tokens.get(&id)
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
        if id == 0 {
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

        while next_id != 0 {
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
            tok.imp_tag = Some(0);
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
        while cur_id != 0 {
            let anc = self.tokens.get(&cur_id).unwrap();
            cur_id = anc.parent;

            ancestors.push(self.tokens.get(&cur_id).unwrap());
        }
        ancestors
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
        while cur_node != 0 {
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
        let mut tree = Tree::new(typ);
        tree.create_tree(obj, None);
        tree.fix_sizes(false);
        tree.label_tree();
        tree
    }

    fn create_tree(&mut self, obj: Element, parent_id: Option<usize>) -> usize {
        let parent = match parent_id {
            Some(id) => id,
            None => 0,
        };
        match obj {
            Element::Sequence(seq) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::Sequence, seq.total_len, vec![], parent, new_id);
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
                token.imp_tag = Some(t.tag.into());
                token.visual_tag = vec![t.tag];

                self.cur_index += 1;

                self.tokens.insert(new_id, token);

                return new_id;
            }
            Element::Set(set) => {
                let new_id = self.cur_index;

                let mut token = Token::new(Types::Set, set.total_len, vec![], parent, new_id);

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
                token.imp_tag = Some(im.tag.into());
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
        let data = self.encode_node(root);
        data
    }

    pub fn label_tree(&mut self) {
        let label_obj = label_tree(&self.obj_type);

        if label_obj.is_none() {
            // Unknown Object Type -> Cant label
            return;
        }

        let label_obj = label_obj.unwrap();
        self.label_tree_rec(0, &label_obj);
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

        if let Some(label) = lobj.label {
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
        let (child_len_full, child_data_len) = self.fix_sizes_rec(&0, mandatory_taint);
        self.tokens.get_mut(&0).unwrap().set_length(child_data_len);
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
        self.print_id_structure_rec(0, &parents);
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
                    node.imp_tag.unwrap(),
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
        }
    }

    pub fn get_node_by_label(&self, label: &str) -> Option<&Token> {
        let id = self.labels.get(label);
        match id {
            Some(id) => Some(self.get_node(*id).unwrap()),
            None => None,
        }
    }

    pub fn get_data_by_label(&self, label: &str) -> Option<Vec<u8>> {
        let id = self.labels.get(label);
        match id {
            Some(id) => Some(self.encode_node(self.get_node(*id).unwrap())),
            None => None,
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
}

impl fmt::Debug for Tree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string(0, 0).1)
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

fn int_to_hex(v: u8) -> u8 {
    let hex_integer: u8 = u8::from_str_radix(&v.to_string(), 16).unwrap();
    hex_integer
}
