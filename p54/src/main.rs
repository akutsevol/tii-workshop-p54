use rand::Rng;

fn main() {
    use p54::{aes128_load_key,aes128_encode,aes128_decode, is_aes_ni_available,encrypt8, decrypt8};


    if is_aes_ni_available() {
        let plain = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
        let key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let cipher = [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32];
        let mut computed_cipher = [0u8; 16];
        let mut computed_plain = [0u8; 16];
    
        let keys = aes128_load_key(&key);
    
        println!("plain_text: {:x?}", plain);
        println!("enc_key: {:x?}", key);
        println!("cipher: {:x?}", cipher);
        // print_m128i_array_as_hex("", &keys);
        
        aes128_encode(&plain, &mut computed_cipher, &keys);
        println!("Encrypted block (aes128_encode): {:x?}", computed_cipher);
    
        aes128_decode(&cipher, &mut computed_plain, &keys);
        println!("Decrypted block (aes128_decode): {:x?}", computed_plain);
    
        println!("");
    
        let mut blocks = [0u8; 128];
        rand::thread_rng().try_fill(&mut blocks).unwrap();

        println!("Original blocks: {:?}", blocks);
        let mut computed_cipher_128 = [0u8; 128];
        let mut computed_plain_128 = [0u8; 128];
    
        encrypt8(&blocks, &mut computed_cipher_128, &keys);
        println!("Encrypted blocks (encrypt8): {:?}", computed_cipher_128);
        
        decrypt8(&computed_cipher_128, &mut computed_plain_128, &keys);
        println!("Decrypted blocks (decrypt8): {:?}", computed_plain_128);
    } else {
        println!("AES-NI is not available.");
    }
}