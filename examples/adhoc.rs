use itm_decode::Decoder;

fn main() {
    let bytes = include_bytes!("./itm.bin");
    let mut decoder = Decoder::new();
    decoder.feed(bytes.to_vec());

    loop {
        match decoder.pull() {
            Ok(Some(packet)) => println!("{:?}", packet),
            Ok(None) => break,
            Err(e) => println!("Error: {:?}", e),
        }
    }
}
