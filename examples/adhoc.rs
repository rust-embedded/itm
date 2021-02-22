use itm_decode::Decoder;

fn main() {
    let bytes = include_bytes!("./itm.bin");
    let mut decoder = Decoder::new();
    decoder.feed(bytes.to_vec());

    while let Some(packet) = decoder.pull() {
        println!("{:?}", packet);
    }
}
