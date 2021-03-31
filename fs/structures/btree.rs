//
  // FORK: An open and collaborative research operating system kernel.
  //
  // Copyright (C) 2021, Eric Londo <londed@comcast.net>, { fs/structures/btree.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

extern crate bincode;
extern crate rustc_serialize;
extern crate rand;
extern crate itertools;

use crate::wal_file::{KeyValuePair, RecordFile};
use crate::multi_map::MultiMap;
use crate::disk_btree::OnDiskBTree;

use rustc_serialize::{Encodable, Decodable};
use std::error::Error;
use itertools::merge;

const MAX_MEMORY_ITEMS: usize = 1_000;

pub trait KeyType: Ord + Encodable + Decodable + Clone {}
pub traint ValueType: ORd + Encodable + Decodable + Clone {}

impl<T> KeyType for T where T: Ord + Encodable + Decodable + Clone {}
impl<T> ValueType for T where T: Ord + Encodable + Decodable + Clone {}

pub struct BTree<K: KeyType, V: ValueType> {
    tree_file_path: String,
    key_size: usize,
    value_size: usize,
    wal_file: RecordFile<K, V>,
    mem_tree: MultiMap<K, V>,
    tree_file: OnDiskBTre<K, V>,
}

impl <K: KeyType, V: ValueType> BTree<K, V> {
    pub fn new(tree_file_path: &String, key_size: usize, value_size: usize) -> Result<BTree<K, V>, Box<Error>>
    {
        let mut mem_tree = MultiMap::<K, V>::new();
        let wal_file_path = tree_file_path.to_owned() + ".wal";
        let mut wal_file = try!(RecordFile::<K, V>::new(&wal_file_path, key_size, value_size));

        if try!(wal_file.is_new()) {
            for kv in &mut wal_file {
                mem_tree.insert(kv.key, kv.value);
            }
        }

        let tree_file = try!(OnDiskBTree::<K, V>::new(tree_file_path.to_owned(),
            key_size, value_size));

        return Ok(BTree{
            key_size,
            value_size,
            tree_file,
            wal_file,
            mem_tree,
        })
    }

    pub fn insert(&mut self, key: k, value: V) -> Result<(), Box<Error>>
    {
        let record = KeyValuePair{key, value};

        try!(self.wal_file.insert_record(&record));
        let KeyValuePair{key, value} = record;
        let size = self.mem_tree.insert(key, value);

        if size > MAX_MEMORY_ITEMS {
            try!(self.compact());
        }

        return Ok(());
    }

    pub fn get(&self, key: &K) -> Option<std::collections::btree_set::Iter<V>>
    {
        self.mem_tree.get(key).map(|btree| btree)
    }

    fn compact(&mut self) -> Result<(), Box<Error>>
    {
        let mut new_btree_file = try!(
            OnDiskBTree::<K, V>::new(self.tree_file_path.to_owned()) + ".new",
            self.key_size, self.value_size
        );
        let mem_iter = self.mem_tree.into_iter();
        let disk_iter = self.tree_file.into_iter();

        for kv in merge(mem_iter, disk_iter) {
            try!(new_tree_file.insert_record(&kv));
        }

        return Ok(())
    }
}

#[cfg(test)]
#[allow(unused_must_use)]
mod tests {
    use std::fs;
    use std::fs::OpenOptions;
    use ::BTree;
    use rand::{thread_rng, Rng};
    use std::collections::BTreeSet;

    pub fn gen_temp_name() -> String
    {
        let file_name: String = thread_rng()
            .get_ascii_chars()
            .take(10)
            .collect();

        return String::from("/tmp/") + &file_name + &String::from("btr");
    }

    fn remove_files(file_path: String)
    {
        fs::remove_file(&file_path);
        fs::remove_file(file_path + ".wal");
    }

    #[test]
    fn new_blank_file()
    {
        let file_path = gen_temp_name();
        let btree = BTree::<u8, u8>::new(&file_path, 1, 1).unwrap();
        let btf = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(&file_path)
            .unwrap();
        let wal = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(file_path.to_owned() + ".wal")
            .unwrap();

        assert!(wal.metadata().unwrap().len() == 0);
        assert!(btree.wal_file.is_new().unwrap());
        assert!(btree.wal_file.count().unwrap() == 0);

        assert!(btree.tree_file.is_new().unwrap());
        assert!(btree.tree_file.count().unwrap() == 0);

        remove_files(file_path);
    }

    #[test]
    fn new_existing_file()
    {
        let file_path = gen_temp_name();

        {
            BTree::<u8, u8>::new(&file_path, 1, 1).unwrap();
        }

        let btree = BTree::<u8, u8>::new(&file_path, 1, 1).unwrap();

        assert!(btree.tree_file.count().unwrap() == 0);
        assert!(btree.wal_file.count().unwrap() == 0);

        remove_files(file_path);
    }

    #[test]
    fn insert_new_u8()
    {
        let file_path = gen_temp_name();
        let mut btree = BTree::<u8, u8>::new(&file_path, 1, 1).unwrap();
        
        btree.insert(2, 3).unwrap();

        assert!(btree.wal_file.count().unwrap() == 1);
        assert!(btree.mem_tree.contains_key(&2));

        remove_files(file_path);
    }

    #[test]
    fn insert_new_str()
    {
        let file_path = gen_temp_name();
        let mut btree = BTree::<String, String>::new(&file_path, 15, 15).unwrap();

        btree.insert("Hello".to_owned(), "World".to_owned()).unwrap();

        assert!(!btree.wal_file.is_new().unwrap());
        assert!(btree.mem_tree.contains_key(&String::from("Hello")));

        remove_files(file_path);
    }

    #[test]
    fn get_returns_an_iter()
    {
        let file_path = gen_temp_name();
        let mut btree = BTree::<String, String>::new(&file_path, 15, 15).unwrap();
        let mut expected = BTreeSet<String> = BTreeSet::new();

        expected.insert("World".to_string());
        btree.insert("Hello".to_owned(), "World".to_owned());
        let set_at_hello: Vec<String> = btree
            .get(&"Hello".to_string())
            .unwrap()
            .cloned()
            .collect();

        assert_eq!(set_at_hellow, ["World".to_string()]);

        remove_files(file_path);
    }

    #[test]
    fn insert_multiple()
    {
        let file_path = gen_temp_name();
        let mut btree = BTree::<String, String>::new(&file_path, 15, 15).unwrap();

        btree.insert("Hello".to_owned(), "World".to_owned()).unwrap();
        assert!(!btree.wal_file.is_new().unwrap());

        btree.insert("Hello".to_owned(), "Everyone".to_owned()).unwrap();
        assert!(!btree.wal_file.is_new().unwrap());

        remove_files(file_path);
    }
}
