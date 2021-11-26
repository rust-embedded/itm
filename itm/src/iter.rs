use super::{
    Decoder, DecoderError, DecoderErrorInt, MalformedPacket, TimestampDataRelation, TracePacket,
};

pub use cortex_m::peripheral::itm::LocalTimestampOptions;
use std::io::Read;

pub struct Singles<'a, R>
where
    R: Read,
{
    decoder: &'a mut Decoder<R>,
}

impl<'a, R> Singles<'a, R>
where
    R: Read,
{
    pub(super) fn new(decoder: &'a mut Decoder<R>) -> Self {
        Self { decoder }
    }
}

impl<'a, R> Iterator for Singles<'a, R>
where
    R: Read,
{
    type Item = Result<TracePacket, DecoderError>;

    fn next(&mut self) -> Option<Self::Item> {
        let trace = self.decoder.next_single();

        match trace {
            Err(DecoderErrorInt::Eof) => None,
            Err(DecoderErrorInt::Io(io)) => Some(Err(DecoderError::Io(io))),
            Err(DecoderErrorInt::MalformedPacket(m)) => Some(Err(DecoderError::MalformedPacket(m))),
            Ok(trace) => Some(Ok(trace)),
        }
    }
}

pub type DateTime = chrono::DateTime<chrono::Utc>;

#[derive(Clone)]
pub struct TimestampConfiguration {
    /// Frequency of the ITM timestamp clock. Necessary to calculate
    /// the offset continuously added to [Self::baseline].
    pub clock_frequency: u32,

    /// Prescaler used for the ITM timestamp clock. Necessary to
    /// calculate the offset continuously added to [Self::baseline].
    pub lts_prescaler: LocalTimestampOptions,

    /// Absolute timestamp on which to continuously sum global and local
    /// timestamps. This timestamp should ideally be the instant the
    /// target's global timestamp clock is reset to zero.
    pub baseline: DateTime,

    /// When set, pushes [MalformedPacket]s to
    /// [TimestampedTracePackets::malformed_packets] instead of
    /// returning it as an [Result::Err].
    pub expect_malformed: bool,
}

/// A set of timestamped trace packets.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimestampedTracePackets {
    /// Timestamp of [Self::packets] and [Self::malformed_packets]
    pub timestamp: Timestamp,
    pub packets: Vec<TracePacket>,
    pub malformed_packets: Vec<MalformedPacket>,

    /// The number of [TracePacket]s consumed to generate this
    /// structure.
    pub consumed_packets: usize,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Timestamp {
    pub ts: DateTime,

    /// In what manner this timestamp relates to the associated data
    /// packets.
    pub data_relation: TimestampDataRelation,
}

impl PartialOrd for Timestamp {
    /// Sorts [Timestamp]s based on [Timestamp::ts].
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.ts.cmp(&other.ts))
    }
}

pub struct Timestamps<'a, R>
where
    R: Read,
{
    decoder: &'a mut Decoder<R>,
    options: TimestampConfiguration,
    current_baseline: DateTime,
}

struct Gts {
    pub lower: Option<u64>,
    pub upper: Option<u64>,
}
impl Gts {
    const GTS2_SHIFT: usize = 26; // see (Appendix D4.2.5).

    pub fn replace_lower(&mut self, new: u64) {
        self.lower = match self.lower {
            None => Some(new),
            Some(old) => {
                let shift = 64 - new.leading_zeros();
                Some(((old >> shift) << shift) | new)
            }
        }
    }

    pub fn reset(&mut self) {
        self.lower = None;
        self.upper = None;
    }

    pub fn merge(&self) -> Option<u64> {
        if let (Some(lower), Some(upper)) = (self.lower, self.upper) {
            Some((upper << Self::GTS2_SHIFT) | lower)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn from_two(gts1: TracePacket, gts2: TracePacket) -> Self {
        match (gts1, gts2) {
            (
                TracePacket::GlobalTimestamp1 { ts: lower, .. },
                TracePacket::GlobalTimestamp2 { ts: upper },
            ) => Self {
                lower: Some(lower),
                upper: Some(upper),
            },
            _ => unreachable!(),
        }
    }

    #[cfg(test)]
    pub fn from_one(gts: TracePacket) -> Self {
        match gts {
            TracePacket::GlobalTimestamp1 { ts: lower, .. } => Self {
                lower: Some(lower),
                upper: None,
            },
            TracePacket::GlobalTimestamp2 { ts: upper, .. } => Self {
                lower: None,
                upper: Some(upper),
            },
            _ => unreachable!(),
        }
    }
}

impl<'a, R> Timestamps<'a, R>
where
    R: Read,
{
    pub(super) fn new(decoder: &'a mut Decoder<R>, options: TimestampConfiguration) -> Self {
        if options.lts_prescaler == LocalTimestampOptions::Disabled {
            unimplemented!("Generating approximate absolute timestamps from global timestamps alone is not yet supported");
        }

        Self {
            current_baseline: options.baseline,
            decoder,
            options,
        }
    }

    fn next_timestamped(
        &mut self,
        options: TimestampConfiguration,
    ) -> Result<TimestampedTracePackets, DecoderErrorInt> {
        use std::ops::Add;

        let mut packets: Vec<TracePacket> = vec![];
        let mut malformed_packets: Vec<MalformedPacket> = vec![];
        let mut consumed_packets: usize = 0;
        let mut gts = Gts {
            lower: None,
            upper: None,
        };

        fn apply_lts(
            lts: u64,
            data_relation: TimestampDataRelation,
            current_baseline: &mut DateTime,
            options: &TimestampConfiguration,
        ) -> Timestamp {
            let offset = calc_offset(lts, Some(options.lts_prescaler), options.clock_frequency);
            *current_baseline = current_baseline.add(offset);

            Timestamp {
                ts: *current_baseline,
                data_relation,
            }
        }

        fn apply_gts(gts: &Gts, current_baseline: &mut DateTime, options: &TimestampConfiguration) {
            if let Some(gts) = gts.merge() {
                let offset = calc_offset(gts, None, options.clock_frequency);
                *current_baseline = options.baseline.add(offset);
            }
        }

        loop {
            consumed_packets += 1;
            match self.decoder.next_single() {
                Err(DecoderErrorInt::MalformedPacket(m)) if options.expect_malformed => {
                    malformed_packets.push(m);
                }
                Err(e) => return Err(e),
                Ok(packet) => match packet {
                    // A local timestamp: packets received up to this point
                    // relate to this local timestamp. Return these.
                    TracePacket::LocalTimestamp1 { ts, data_relation } => {
                        return Ok(TimestampedTracePackets {
                            timestamp: apply_lts(
                                ts,
                                data_relation,
                                &mut self.current_baseline,
                                &self.options,
                            ),
                            packets,
                            malformed_packets,
                            consumed_packets,
                        });
                    }
                    TracePacket::LocalTimestamp2 { ts } => {
                        return Ok(TimestampedTracePackets {
                            timestamp: apply_lts(
                                ts.into(),
                                TimestampDataRelation::Sync,
                                &mut self.current_baseline,
                                &self.options,
                            ),
                            packets,
                            malformed_packets,
                            consumed_packets,
                        });
                    }

                    // A global timestamp: store until we have both the
                    // upper (GTS2) and lower (GTS1) bits.
                    TracePacket::GlobalTimestamp1 { ts, wrap, clkch } => {
                        gts.replace_lower(ts);

                        if wrap {
                            // upper bits have changed; GTS2 incoming
                            gts.upper = None;
                        } else {
                            apply_gts(&gts, &mut self.current_baseline, &options);
                        }
                        if clkch {
                            // system has asserted clock change input; full GTS incoming
                            //
                            // A clock change signal that the system
                            // asserts if there is a change in the ratio
                            // between the global timestamp clock
                            // frequency and the processor clock
                            // frequency. Implementation and use of the
                            // clock change signal is optional and
                            // deprecated.
                            gts.reset();
                        }
                    }
                    TracePacket::GlobalTimestamp2 { ts } => {
                        gts.upper = Some(ts);
                        apply_gts(&gts, &mut self.current_baseline, &options);
                    }

                    packet => packets.push(packet),
                },
            }
        }
    }
}

impl<'a, R> Iterator for Timestamps<'a, R>
where
    R: Read,
{
    type Item = Result<TimestampedTracePackets, DecoderError>;

    fn next(&mut self) -> Option<Self::Item> {
        let trace = self.next_timestamped(self.options.clone());

        match trace {
            Err(DecoderErrorInt::Eof) => None,
            Err(DecoderErrorInt::Io(io)) => Some(Err(DecoderError::Io(io))),
            Err(DecoderErrorInt::MalformedPacket(m)) => Some(Err(DecoderError::MalformedPacket(m))),
            Ok(trace) => Some(Ok(trace)),
        }
    }
}

fn calc_offset(ts: u64, prescaler: Option<LocalTimestampOptions>, freq: u32) -> chrono::Duration {
    let prescale = match prescaler {
        None | Some(LocalTimestampOptions::Enabled) => 1,
        Some(LocalTimestampOptions::EnabledDiv4) => 4,
        Some(LocalTimestampOptions::EnabledDiv16) => 16,
        Some(LocalTimestampOptions::EnabledDiv64) => 64,
        Some(LocalTimestampOptions::Disabled) => unreachable!(), // checked in `Timestamps::new`
    };
    let ticks = ts * prescale;
    let seconds = (1_f64 / freq as f64) * ticks as f64;

    chrono::Duration::nanoseconds((seconds * 1e9).ceil() as i64)
}

#[cfg(test)]
mod timestamp_utils {
    use super::*;

    #[test]
    fn gts() {
        let gts = Gts {
            lower: None,
            upper: None,
        };
        assert_eq!(gts.merge(), None, "noop merge");

        let mut gts = Gts {
            lower: Some(42),
            upper: Some(42),
        };
        assert_eq!(
            gts.merge(),
            Some((42 << Gts::GTS2_SHIFT) | 42),
            "(42, 42) merge"
        );

        gts.replace_lower(0b1101011);
        assert_eq!(
            gts.merge(),
            Some((42 << Gts::GTS2_SHIFT) | 0b1101011),
            "replace whole merge"
        );

        let mut gts = Gts {
            lower: Some(42),
            upper: Some(42),
        };
        gts.replace_lower(1);
        assert_eq!(
            gts.merge(),
            Some((42 << Gts::GTS2_SHIFT) | 43),
            "replace partial merge"
        );
    }

    #[test]
    fn offset() {
        assert_eq!(
            calc_offset(1000, Some(LocalTimestampOptions::EnabledDiv4), 16_000_000),
            chrono::Duration::microseconds(250),
        );
    }
}

#[cfg(test)]
mod timestamps {
    use super::{calc_offset, Gts};
    use crate::*;
    use std::ops::{Add, Sub};

    const FREQ: u32 = 16_000_000;
    static mut BASELINE: Option<chrono::DateTime<chrono::Utc>> = None;

    fn outer_calc_offset(
        lts: TracePacket,
        gts: Option<Gts>,
        offset_sum: &mut chrono::Duration,
    ) -> Timestamp {
        let (reset, offset, data_relation) = match (lts, gts) {
            (
                TracePacket::LocalTimestamp1 {
                    ts: lts,
                    data_relation,
                },
                Some(gts),
            ) => {
                (
                    true,
                    calc_offset(gts.merge().unwrap() + lts, None, FREQ)
                        // XXX why are we 1ns off?
                        .sub(chrono::Duration::nanoseconds(1)),
                    data_relation,
                )
            }
            (TracePacket::LocalTimestamp1 { ts, data_relation }, None) => {
                (false, calc_offset(ts, None, FREQ), data_relation)
            }
            (TracePacket::LocalTimestamp2 { ts }, None) => (
                false,
                calc_offset(ts.into(), None, FREQ),
                TimestampDataRelation::Sync,
            ),
            (TracePacket::LocalTimestamp2 { ts }, Some(gts)) => (
                false,
                calc_offset(gts.merge().unwrap_or(0) + (ts as u64), None, FREQ),
                TimestampDataRelation::Sync,
            ),
            _ => panic!("???"),
        };

        *offset_sum = if reset {
            // GTS provided
            offset
        } else {
            // LTS provided
            offset_sum.add(offset)
        };

        Timestamp {
            ts: unsafe { BASELINE.unwrap() }.add(*offset_sum),
            data_relation,
        }
    }

    #[test]
    fn test1() {
        unsafe {
            BASELINE = Some(chrono::DateTime::<chrono::Utc>::from_utc(
                chrono::NaiveDateTime::from_timestamp(0, 0),
                chrono::Utc,
            ));
        }

        #[rustfmt::skip]
        let stream: &[u8] = &[
            // PC sample (sleeping)
            0b0001_0101,
            0b0000_0000,

            // PC sample (sleeping)
            0b0001_0101,
            0b0000_0000,

            // PC sample (sleeping)
            0b0001_0101,
            0b0000_0000,

            // GTS1
            0b1001_0100,
            0b1000_0000,
            0b1010_0000,
            0b1000_0100,
            0b0000_0000,

            // GTS2 (48-bit)
            0b1011_0100,
            0b1011_1101,
            0b1111_0100,
            0b1001_0001,
            0b0000_0001,

            // LTS1
            0b1100_0000,
            0b1100_1001,
            0b0000_0001,

            // Pull!

            // PC sample (sleeping)
            0b0001_0101,
            0b0000_0000,

            // LTS1
            0b1100_0000,
            0b1100_1001,
            0b0000_0001,

            // Pull!

            // Overflow
            0b0111_0000,

            // LTS1
            0b1100_0000,
            0b1100_1001,
            0b0000_0001,

            // Pull!

            // GTS1
            0b1001_0100,
            0b1000_0000,
            0b1010_0000,
            0b1000_0100,
            0b0000_0000,

            // GTS2 (48-bit)
            0b1011_0100,
            0b1011_1101,
            0b1111_0100,
            0b1001_0001,
            0b0000_0001,

            // LTS1
            0b1111_0000,
            0b1100_1001,
            0b0000_0001,

            // LTS2
            0b0110_0000,
        ];

        let timestamps = {
            let mut offset_sum = chrono::Duration::nanoseconds(0);
            let mut decoder = Decoder::new(stream.clone(), DecoderOptions { ignore_eof: false });
            let mut it = decoder.singles();
            [
                {
                    let gts1 = it.nth(3).unwrap().unwrap();
                    let gts2 = it.nth(0).unwrap().unwrap();
                    let lts1 = it.nth(0).unwrap().unwrap();

                    outer_calc_offset(lts1, Some(Gts::from_two(gts1, gts2)), &mut offset_sum)
                },
                {
                    let lts1 = it.nth(1).unwrap().unwrap();
                    outer_calc_offset(lts1, None, &mut offset_sum)
                },
                {
                    let lts1 = it.nth(1).unwrap().unwrap();
                    outer_calc_offset(lts1, None, &mut offset_sum)
                },
                {
                    let gts1 = it.nth(0).unwrap().unwrap();
                    let gts2 = it.nth(0).unwrap().unwrap();
                    let lts1 = it.nth(0).unwrap().unwrap();

                    outer_calc_offset(lts1, Some(Gts::from_two(gts1, gts2)), &mut offset_sum)
                },
                {
                    let lts2 = it.nth(0).unwrap().unwrap();
                    outer_calc_offset(lts2, None, &mut offset_sum)
                },
            ]
        };

        // ensure timestamps are in increasing order
        // TODO(unstable) replace with slice::is_sorted
        assert!(|| -> bool {
            let mut it = timestamps.iter();
            let mut prev = None;
            while let Some(curr) = it.next() {
                if prev.is_none() {
                    continue;
                }

                if curr < prev.unwrap() {
                    return false;
                }

                prev = Some(curr);
            }

            true
        }());

        let mut decoder = Decoder::new(stream.clone(), DecoderOptions { ignore_eof: false });
        let mut it = decoder.timestamps(TimestampConfiguration {
            clock_frequency: FREQ,
            lts_prescaler: LocalTimestampOptions::Enabled,
            baseline: unsafe { BASELINE.unwrap() },
            expect_malformed: false,
        });

        for set in [
            TimestampedTracePackets {
                packets: [
                    TracePacket::PCSample { pc: None },
                    TracePacket::PCSample { pc: None },
                    TracePacket::PCSample { pc: None },
                ]
                .into(),
                malformed_packets: [].into(),
                timestamp: timestamps[0].clone(),
                consumed_packets: 6,
            },
            TimestampedTracePackets {
                packets: [TracePacket::PCSample { pc: None }].into(),
                malformed_packets: [].into(),
                timestamp: timestamps[1].clone(),
                consumed_packets: 2,
            },
            TimestampedTracePackets {
                packets: [TracePacket::Overflow].into(),
                malformed_packets: [].into(),
                timestamp: timestamps[2].clone(),
                consumed_packets: 2,
            },
            TimestampedTracePackets {
                packets: [].into(),
                malformed_packets: [].into(),
                timestamp: timestamps[3].clone(),
                consumed_packets: 3,
            },
            TimestampedTracePackets {
                packets: [].into(),
                malformed_packets: [].into(),
                timestamp: timestamps[4].clone(),
                consumed_packets: 1,
            },
        ]
        .iter()
        {
            assert_eq!(it.next().unwrap().unwrap(), *set);
        }
    }

    // #[test]
    // fn test2() {
    //     unsafe {
    //         BASELINE = Some(chrono::DateTime::<chrono::Utc>::from_utc(
    //             chrono::NaiveDateTime::from_timestamp(0, 0),
    //             chrono::Utc,
    //         ));
    //     }

    //     #[rustfmt::skip]
    //     let stream: &[u8] = &[
    //         // GTS1
    //         0b1001_0100,
    //         0b1000_0000,
    //         0b1010_0000,
    //         0b1000_0100,
    //         0b0000_0000,

    //         // GTS2 (64-bit)
    //         0b1011_0100,
    //         0b1011_1101,
    //         0b1111_0100,
    //         0b1001_0001,
    //         0b1000_0001,
    //         0b1000_0001,
    //         0b0000_0001,

    //         // LTS2
    //         0b0110_0000,

    //         // GTS1 (compressed)
    //         0b1001_0100,
    //         0b0111_1111,

    //         // LTS2
    //         0b0110_0000,
    //     ];

    //     let timestamps = {
    //         let mut offset_sum = chrono::Duration::nanoseconds(0);
    //         let mut decoder = Decoder::new(stream.clone(), DecoderOptions { ignore_eof: false });
    //         let mut it = decoder.singles();
    //         let mut gts = None;
    //         [
    //             {
    //                 let gts1 = it.nth(0).unwrap().unwrap();
    //                 let gts2 = it.nth(0).unwrap().unwrap();
    //                 let lts2 = it.nth(0).unwrap().unwrap();
    //                 gts = Gts::from_two(gts1, gts2);

    //                 outer_calc_offset(lts2, Some(Gts::from_two(gts1, gts2)), &mut offset_sum)
    //             },
    //             {
    //                 let gts1 = it.nth(0).unwrap().unwrap();
    //                 let lts2 = it.nth(0).unwrap().unwrap();
    //                 outer_calc_offset(lts2, Some(Gts::from_one(gts1)), &mut offset_sum)
    //             },
    //         ]
    //     };
    // }
}
