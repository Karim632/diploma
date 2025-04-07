use std::{fs::write, path::{Path, PathBuf}};

pub mod parser;
pub mod util;

fn main() {
    let class_file = match parser::parse_class_file("Test.class") {
        Ok(result) => result,
        Err(err) => panic!("{}", err),
    };

    println!("{:#?}", class_file);
    write("out_test.txt", format!("{:#?}", class_file)).unwrap();
}
