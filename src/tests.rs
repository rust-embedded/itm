use std::io::Cursor;

use crate::{packet::Function, Error, Packet, Stream};

#[test]
fn synchronization() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // OK
            0,
            0,
            0,
            0,
            0,
            0b1000_0000,
            // malformed
            0,
            0,
            0,
            0,
            1,
        ]),
        false,
    );

    // OK
    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Synchronization(s) => assert_eq!(s.len(), 6),
        _ => panic!(),
    }

    // malformed
    match stream.next().unwrap().unwrap() {
        Err(Error::MalformedPacket { header, len }) => {
            assert_eq!(header, 0);
            assert_eq!(len, 4);
        }
        _ => panic!(),
    }

    // next byte should be a non-zero byte
    match stream.next().unwrap() {
        Some(Err(Error::MalformedPacket { header, len })) => {
            assert_eq!(header, 1);
            assert_eq!(len, 1);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn overflow() {
    let mut stream = Stream::new(Cursor::new(&[0x70]), false);

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Overflow => {}
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn instrumentation() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // port 0; 1 byte
            0x01, 0x10, //
            // port 1; 2 bytes
            0x0a, 0x30, 0x20, //
            // port 2; 4 bytes
            0x13, 0x70, 0x60, 0x50, 0x40,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(i) => {
            assert_eq!(i.port(), 0);
            assert_eq!(i.payload(), &[0x10]);
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(i) => {
            assert_eq!(i.port(), 1);
            assert_eq!(i.payload(), &[0x30, 0x20]);
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(i) => {
            assert_eq!(i.port(), 2);
            assert_eq!(i.payload(), &[0x70, 0x60, 0x50, 0x40]);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn lts1() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Instrumentation
            0x01, 0x00, //
            // LTS1
            0xc0, 0x81, 0x81, 0x81, 0x01, //
            // Instrumentation
            0x01, 0x00, //
            // LTS1
            0xc0, 0x81, 0x81, 0x01, //
            // Instrumentation
            0x01, 0x00, //
            // LTS1
            0xc0, 0x81, 0x01, //
            // Instrumentation
            0x01, 0x00, //
            // LTS1
            0xc0, 0x01,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::LocalTimestamp(lt) => {
            assert!(lt.is_precise());
            assert_eq!(lt.delta(), 1 + (1 << 7) + (1 << 14) + (1 << 21));
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::LocalTimestamp(lt) => {
            assert!(lt.is_precise());
            assert_eq!(lt.delta(), 1 + (1 << 7) + (1 << 14));
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::LocalTimestamp(lt) => {
            assert!(lt.is_precise());
            assert_eq!(lt.delta(), 1 + (1 << 7));
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::LocalTimestamp(lt) => {
            assert!(lt.is_precise());
            assert_eq!(lt.delta(), 1);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn lts2() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Instrumentation
            0x01, 0x10, //
            // LTS2
            0x40,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::LocalTimestamp(lt) => {
            assert!(lt.is_precise());
            assert_eq!(lt.delta(), 4);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn gts1() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Instrumentation
            0x01, 0x00, //
            // GTS1
            0x94, 0x7f, //
            // Instrumentation
            0x01, 0x00, //
            // GTS1
            0x94, 0xff, 0x7f, //
            // Instrumentation
            0x01, 0x00, //
            // GTS1
            0x94, 0xff, 0xff, 0x7f, //
            // Instrumentation
            0x01, 0x00, //
            // GTS1
            0x94, 0xff, 0xff, 0xff, 0x7f,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS1(gt) => {
            assert_eq!(gt.bits(), 0x7f);
            assert!(!gt.has_clock_changed());
            assert!(!gt.has_wrapped());
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS1(gt) => {
            assert_eq!(gt.bits(), 0x7f + (0x7f << 7));
            assert!(!gt.has_clock_changed());
            assert!(!gt.has_wrapped());
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS1(gt) => {
            assert_eq!(gt.bits(), 0x7f + (0x7f << 7) + (0x7f << 14));
            assert!(!gt.has_clock_changed());
            assert!(!gt.has_wrapped());
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::Instrumentation(_) => {}
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS1(gt) => {
            assert_eq!(gt.bits(), 0x7f + (0x7f << 7) + (0x7f << 14) + (0x1f << 21));
            assert!(gt.has_clock_changed());
            assert!(gt.has_wrapped());
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn gts2() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // 5-byte GTS2
            0xb4, 0xff, 0xff, 0xff, 0x01, //
            // 7-byte GTS2
            0xb4, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS2(gt) => {
            assert_eq!(gt.bits(), (1 << 22) - 1);
            assert!(!gt.is_64_bit());
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::GTS2(gt) => {
            assert_eq!(gt.bits(), (1 << 38) - 1);
            assert!(gt.is_64_bit());
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn stimulus_port_page() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Stimulus Port Page
            0x08,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::StimulusPortPage(spp) => {
            assert_eq!(spp.page(), 0);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn event_counter() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Event Counter
            0x05, 0x04,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::EventCounter(ec) => {
            assert!(ec.sleep());
            assert!(!ec.exc());
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn exception_trace() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Exception Trace
            0x0e, 0x10, 0x10, //
            // Exception Trace
            0x0e, 0x10, 0x20, //
            // Exception Trace
            0x0e, 0x00, 0x30,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::ExceptionTrace(et) => {
            assert_eq!(et.number(), 0x10);
            assert_eq!(et.function(), Function::Enter);
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::ExceptionTrace(et) => {
            assert_eq!(et.number(), 0x10);
            assert_eq!(et.function(), Function::Exit);
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::ExceptionTrace(et) => {
            assert_eq!(et.number(), 0);
            assert_eq!(et.function(), Function::Return);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn periodic_pc_sample() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Periodic PC Sleep
            0x15, 0x00, //
            // Full Periodic PC Sample
            0x17, 0x00, 0x00, 0x00, 0x80,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::PeriodicPcSample(pps) => {
            assert_eq!(pps.pc(), None);
        }
        _ => panic!(),
    }

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::PeriodicPcSample(pps) => {
            assert_eq!(pps.pc(), Some(0x8000_0000));
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn data_trace_pc_value() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Data Trace PC Value
            0x47, 0x00, 0x00, 0x00, 0x80,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::DataTracePcValue(pps) => {
            assert_eq!(pps.comparator(), 0);
            assert_eq!(pps.pc(), 0x8000_0000);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn data_trace_address() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Data Trace Address
            0x4e, 0x12, 0x34,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::DataTraceAddress(pps) => {
            assert_eq!(pps.comparator(), 0);
            assert_eq!(pps.address(), 0x3412);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}

#[test]
fn data_trace_data_value() {
    let mut stream = Stream::new(
        Cursor::new(&[
            // Data Trace Data Value
            0x85, 0x12,
        ]),
        false,
    );

    match stream.next().unwrap().unwrap().unwrap() {
        Packet::DataTraceDataValue(pps) => {
            assert!(pps.read_access());
            assert_eq!(pps.comparator(), 0);
            assert_eq!(pps.value(), &[0x12]);
        }
        _ => panic!(),
    }

    // EOF
    assert!(stream.next().unwrap().is_none());
}
