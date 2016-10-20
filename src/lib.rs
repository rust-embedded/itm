//! Tool to parse and dump [ITM] packets
//!
//! [ITM]: http://infocenter.arm.com/help/topic/com.arm.doc.ddi0314h/Chdbicbg.html
//!
//! Right now, this tool only handles instrumentation packets from the stimulus
//! port 0.
//!
//! # Usage
//!
//! ``` text
//! $ itmdump /tmp/itm.fifo
//! ```
//!
//! This will create a named pipe: `/tmp/itm.fifo`. Another application, e.g.
//! OpenOCD, will have to be connected (open+write) to this pipe. Here's an
//! example command for OpenOCD+GDB that does that. (But
//! [read their documentation!]).
//!
//! [read their documentation!]: http://openocd.org/doc/html/Architecture-and-Core-Commands.html
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
//! # References
//!
//! - ARMv7-M Architecture Reference Manual - Appendix D4.2 Packet descriptions
