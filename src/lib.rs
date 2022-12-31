extern crate wasm_bindgen;
use wasm_bindgen::prelude::*;

mod cipher;

#[wasm_bindgen]
pub fn encrypt(password: &str, data: &str) -> String {
    cipher::encrypt(password, data)
}

#[wasm_bindgen]
pub fn decrypt(password: &str, data: &str) -> String {
    cipher::decrypt(password, data)
}
