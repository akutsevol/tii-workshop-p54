use std::arch::x86_64::*;
#[allow(unused_imports)]
use rand::prelude::SliceRandom;

const NUM_ROUNDS: usize = 20;

const fn my_mm_shuffle(z: u32, y: u32, x: u32, w: u32) -> i32 {
    ((z << 6) | (y << 4) | (x << 2) | w) as i32
}

unsafe fn aes_128_key_expansion(key: __m128i, keygened: __m128i) -> __m128i {
    unsafe {
        let keygened = _mm_shuffle_epi32(keygened, my_mm_shuffle(3, 3, 3, 3));
        let mut key = key;
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        _mm_xor_si128(key, keygened)
    }
}

pub fn aes128_load_key(key: &[u8; 16]) ->[__m128i; NUM_ROUNDS] {
    let mut key_schedule = [unsafe { _mm_setzero_si128() }; NUM_ROUNDS];
    unsafe {
        key_schedule[0]  = _mm_loadu_si128(key.as_ptr() as *const __m128i);
        key_schedule[1]  = aes_128_key_expansion(key_schedule[0], _mm_aeskeygenassist_si128(key_schedule[0], 0x01));
        key_schedule[2]  = aes_128_key_expansion(key_schedule[1], _mm_aeskeygenassist_si128(key_schedule[1], 0x02));
        key_schedule[3]  = aes_128_key_expansion(key_schedule[2], _mm_aeskeygenassist_si128(key_schedule[2], 0x04));
        key_schedule[4]  = aes_128_key_expansion(key_schedule[3], _mm_aeskeygenassist_si128(key_schedule[3], 0x08));
        key_schedule[5]  = aes_128_key_expansion(key_schedule[4], _mm_aeskeygenassist_si128(key_schedule[4], 0x10));
        key_schedule[6]  = aes_128_key_expansion(key_schedule[5], _mm_aeskeygenassist_si128(key_schedule[5], 0x20));
        key_schedule[7]  = aes_128_key_expansion(key_schedule[6], _mm_aeskeygenassist_si128(key_schedule[6], 0x40));
        key_schedule[8]  = aes_128_key_expansion(key_schedule[7], _mm_aeskeygenassist_si128(key_schedule[7], 0x80));
        key_schedule[9]  = aes_128_key_expansion(key_schedule[8], _mm_aeskeygenassist_si128(key_schedule[8], 0x1B));
        key_schedule[10] = aes_128_key_expansion(key_schedule[9], _mm_aeskeygenassist_si128(key_schedule[9], 0x36));
        
        // generate decryption keys in reverse order.
        // k[10] is shared by last encryption and first decryption rounds
        // k[0] is shared by first encryption round and last decryption round (and is the original user key)
        // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
        key_schedule[11] = _mm_aesimc_si128(key_schedule[9]);
        key_schedule[12] = _mm_aesimc_si128(key_schedule[8]);
        key_schedule[13] = _mm_aesimc_si128(key_schedule[7]);
        key_schedule[14] = _mm_aesimc_si128(key_schedule[6]);
        key_schedule[15] = _mm_aesimc_si128(key_schedule[5]);
        key_schedule[16] = _mm_aesimc_si128(key_schedule[4]);
        key_schedule[17] = _mm_aesimc_si128(key_schedule[3]);
        key_schedule[18] = _mm_aesimc_si128(key_schedule[2]);
        key_schedule[19] = _mm_aesimc_si128(key_schedule[1]);
    }
    key_schedule
}

pub fn aes128_encode(plain_text: &[u8; 16], cipher_text: &mut [u8; 16], key_schedule: &[__m128i; NUM_ROUNDS]) {
    unsafe {
        let mut m = _mm_loadu_si128(plain_text.as_ptr() as *const __m128i);

        m = _mm_xor_si128(m, key_schedule[0]);
        m = _mm_aesenc_si128(m, key_schedule[1]);
        m = _mm_aesenc_si128(m, key_schedule[2]);
        m = _mm_aesenc_si128(m, key_schedule[3]);
        m = _mm_aesenc_si128(m, key_schedule[4]);
        m = _mm_aesenc_si128(m, key_schedule[5]);
        m = _mm_aesenc_si128(m, key_schedule[6]);
        m = _mm_aesenc_si128(m, key_schedule[7]);
        m = _mm_aesenc_si128(m, key_schedule[8]);
        m = _mm_aesenc_si128(m, key_schedule[9]);
        m = _mm_aesenclast_si128(m, key_schedule[10]);

        _mm_storeu_si128(cipher_text.as_mut_ptr() as *mut __m128i, m);
    }
}

pub fn aes128_decode(cipher_text: &[u8; 16], plain_text: &mut [u8; 16], key_schedule: &[__m128i; NUM_ROUNDS]) {
    unsafe {
        let mut m = _mm_loadu_si128(cipher_text.as_ptr() as *const __m128i);

        m = _mm_xor_si128(m, key_schedule[10+0]);
        m = _mm_aesdec_si128(m, key_schedule[10+1]);
        m = _mm_aesdec_si128(m, key_schedule[10+2]);
        m = _mm_aesdec_si128(m, key_schedule[10+3]);
        m = _mm_aesdec_si128(m, key_schedule[10+4]);
        m = _mm_aesdec_si128(m, key_schedule[10+5]);
        m = _mm_aesdec_si128(m, key_schedule[10+6]);
        m = _mm_aesdec_si128(m, key_schedule[10+7]);
        m = _mm_aesdec_si128(m, key_schedule[10+8]);
        m = _mm_aesdec_si128(m, key_schedule[10+9]);
        m = _mm_aesdeclast_si128(m, key_schedule[0]);

        _mm_storeu_si128(plain_text.as_mut_ptr() as *mut __m128i, m);
    }
}

#[allow(dead_code)]
// Encrypt eight 128-bit blocks
pub fn encrypt8(plain_text: &[u8; 128], cipher_text: &mut [u8; 128], key_schedule: &[__m128i; NUM_ROUNDS]) {
    let mut computed_cipher = [0u8; 16];
    let mut cipher_offset = 0;
    for chunk in plain_text.chunks(16) {
        let chunk_array: &[u8; 16] = chunk.try_into().expect("Chunk size is not 16 bytes");
        aes128_encode(chunk_array, &mut computed_cipher, key_schedule);
        cipher_text[cipher_offset..cipher_offset + 16].copy_from_slice(&computed_cipher);
        cipher_offset += 16;
    }
}

#[allow(dead_code)]
// Decrypt eight 128-bit blocks
pub fn decrypt8(cipher_text: &[u8; 128], plain_text: &mut [u8; 128], key_schedule: &[__m128i; NUM_ROUNDS]) {
    let mut computed_plain = [0u8; 16];
    let mut plain_text_offset = 0;
    for chunk in cipher_text.chunks(16) {
        let chunk_array: &[u8; 16] = chunk.try_into().expect("Chunk size is not 16 bytes");
        aes128_decode(chunk_array, &mut computed_plain, key_schedule);
        plain_text[plain_text_offset..plain_text_offset + 16].copy_from_slice(&computed_plain);
        plain_text_offset += 16;
    }
}

#[allow(dead_code)]
pub fn print_m128i_array_as_hex(prefix: &str, arr: &[__m128i]) {
    unsafe {
        print!("{prefix}");
        for m in arr.iter() {
            let mut bytes = [0u8; 16];
            _mm_storeu_si128(bytes.as_mut_ptr() as *mut __m128i, *m);
            print!("[");
            for (i, byte) in bytes.iter().enumerate() {
                print!("{:02x}", byte);
                if i < 15 { print!(" "); }
            }
            println!("]");
        }
    }
}

/// Checks if AES-NI is available at runtime.
pub fn is_aes_ni_available() -> bool {
    is_x86_feature_detected!("aes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_encrypt_decrypt() {
        assert!(is_aes_ni_available(), "AES-NI is not supported on this CPU");
        
        let plain = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        let mut computed_cipher = [0u8; 16];
        let mut computed_plain = [0u8; 16];

        let keys = aes128_load_key(&key);

        aes128_encode(&plain, &mut computed_cipher, &keys);
        aes128_decode(&cipher, &mut computed_plain, &keys);

        assert_eq!(plain, computed_plain);
    }

    #[test]
    fn test_aes128_encrypt8_decrypt8() {
        assert!(is_aes_ni_available(), "AES-NI is not supported on this CPU");

        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let keys = aes128_load_key(&key);

        // build plain_text blocks and randomize it
        let mut blocks = [0u8; 128];
        let mut rng = rand::thread_rng();
        blocks.shuffle(&mut rng);

        let mut computed_cipher = [0u8; 128];
        let mut computed_plain = [0u8; 128];

        encrypt8(&blocks, &mut computed_cipher, &keys);
        decrypt8(&computed_cipher, &mut computed_plain, &keys);

        assert_eq!(blocks, computed_plain);
    }
}