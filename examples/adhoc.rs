use itm_decode::{Decoder, DecoderState};

fn main() {
    let bytes = include_bytes!("./itm.bin");
    let mut decoder = Decoder::new();
    decoder.feed(bytes.to_vec());

    loop {
        match decoder.pull() {
            Ok(Some(packet)) => println!("{:?}", packet),
            Ok(None) => break,
            Err(e) => {
                println!("Error: {:?}", e);
                // naive
                decoder.state = DecoderState::Header;
            }
        }
    }
}
