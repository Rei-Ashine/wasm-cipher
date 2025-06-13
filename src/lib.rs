mod cipher;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn encrypt(password: &str, data: &str) -> Result<String, String> {
    cipher::encrypt(password, data)
}

#[wasm_bindgen]
pub fn decrypt(password: &str, data: &str) -> Result<String, String> {
    cipher::decrypt(password, data)
}
