//! A library and tool (`itmdump`) to parse and dump ARM ITM packets.
//!
//! ## Usage
//!
//! ``` text
//! itmdump  (de13e34 2017-12-19)
//!
//! Reads data from an ARM CPU ITM and decodes it.
//!
//! Input is from an existing file (or named pipe) at a supplied path, or else from standard input.
//!
//! USAGE:
//!     itmdump [FLAGS] [OPTIONS]
//!
//! FLAGS:
//!     -F, --follow     Keep the file open after reading through it and append new output as it is written. Like `tail -f'.
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -f, --file <file>        Path to file (or named pipe) to read from
//!     -s, --stimulus <port>    Stimulus port to extract ITM data for. [default: 0]
//! ```
//!
//! ### Example: reading from saved ITM data in a file
//! ``` text
//! $ itmdump -f /tmp/itm.dump
//! PANIC at 'Hello, world!', examples/panic.rs:13
//! ```
//!
//! ### Example: reading from OpenOCD via a named pipe
//!
//! [OpenOCD][openocd home] is an open-source tool to debug and flash
//! microcontrollers.
//!
//! Reading via a named pipe works well on POSIX machines; e.g. Linux
//! or macOS, but not Windows.
//!
//! ``` text
//! $ mkfifo /tmp/itm.fifo
//! $ itmdump -f /tmp/itm.fifo
//! ```
//!
//! This will create a named pipe: `/tmp/itm.fifo`. Another
//! application, e.g.  OpenOCD, will have to connect to this pipe and
//! write to it. Here's an example command for OpenOCD
//! + GDB that does that. ([OpenOCD documentation on ITM and
//! TPIU][openocd v7m]).
//!
//! [openocd home]: http://openocd.org/
//! [openocd v7m]: http://openocd.org/doc/html/Architecture-and-Core-Commands.html#ARMv7_002dM-specific-commands
//!
//! ``` text
//! (gdb) monitor tpiu config internal /tmp/itm.fifo uart off 8000000
//! ```
//!
//! `itmdump` will read from the pipe, parse the packets and write the payload
//! to `stdout`:
//!
//! ``` text
//! PANIC at 'Hello, world!', examples/panic.rs:13
//! ```
//!
//! ### Example: monitoring a file
//!
//! `itmdump` can monitor a file and dump new ITM data written to it
//! (similar to `tail -f`).
//!
//! This may be useful on Windows especially where POSIX named pipes
//! are not available. Just let OpenOCD capture to a file and monitor
//! it with `itmdump`.
//!
//! ``` text
//! $ itmdump -f /tmp/itm.live -F
//! PANIC at 'Hello, world!', examples/panic.rs:13
//! ```
//!
//! # References
//!
//! - ARMv7-M Architecture Reference Manual - Appendix D4.2 Packet descriptions
//!
//!   Available to download [as a PDF][ARMv7-m]
//!   after a free registration.
//!   [ARMv7-m]: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0403e.b/index.html
//!
//! - [ARM CoreSight Technical Reference Manual section on ITM][CoreSight ITM]
//!   [CoreSight ITM]: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0314h/CAAGGCDH.html
