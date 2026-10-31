//! Virtual FIDO HID device via Linux `/dev/uhid`.

use anyhow::{bail, Context, Result};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use tracing::{debug, info};

use crate::ctaphid::HID_REPORT_SIZE;

const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_DESTROY: u32 = 1;
const BUS_USB: u16 = 0x03;

/// FIDO Alliance HID usage page 0xF1D0, usage 0x01, 64-byte in/out reports.
pub const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F HID Authenticator Device)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xc0, // End Collection
];

/// Packed uhid_event layout matching linux/uhid.h (userspace ABI).
#[repr(C)]
struct UhidEvent {
    etype: u32,
    // Union payload follows; we allocate a large enough buffer.
}

// create2 request fields after type
#[repr(C, packed)]
struct UhidCreate2 {
    name: [u8; 128],
    phys: [u8; 64],
    uniq: [u8; 64],
    rd_size: u16,
    bus: u16,
    vendor: u32,
    product: u32,
    version: u32,
    country: u32,
    rd_data: [u8; 4096],
}

#[repr(C, packed)]
struct UhidInput2 {
    size: u16,
    data: [u8; 4096],
}

#[repr(C, packed)]
struct UhidOutput {
    data: [u8; 4096],
    size: u16,
    rtype: u8,
}

pub struct UhidDevice {
    file: std::fs::File,
}

impl UhidDevice {
    pub fn create(name: &str, vendor: u32, product: u32) -> Result<Self> {
        let path = Path::new("/dev/uhid");
        if !path.exists() {
            bail!("/dev/uhid not found — is the uhid kernel module loaded?");
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc_nonblock())
            .open(path)
            .context("open /dev/uhid — check udev rules / group fidobridge")?;

        let mut create = UhidCreate2 {
            name: [0; 128],
            phys: [0; 64],
            uniq: [0; 64],
            rd_size: FIDO_REPORT_DESCRIPTOR.len() as u16,
            bus: BUS_USB,
            vendor,
            product,
            version: 0x0100,
            country: 0,
            rd_data: [0; 4096],
        };
        copy_cstr(&mut create.name, name);
        copy_cstr(&mut create.phys, "fido-bridge");
        copy_cstr(&mut create.uniq, "fido-bridge-0");
        create.rd_data[..FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(FIDO_REPORT_DESCRIPTOR);

        let mut buf = vec![0u8; 4 + std::mem::size_of::<UhidCreate2>()];
        buf[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
        // SAFETY: plain bytes of packed struct
        let create_bytes = unsafe {
            std::slice::from_raw_parts(
                (&create as *const UhidCreate2) as *const u8,
                std::mem::size_of::<UhidCreate2>(),
            )
        };
        buf[4..].copy_from_slice(create_bytes);

        let mut device = Self { file };
        device.file.write_all(&buf).context("UHID_CREATE2")?;
        info!(
            "created virtual FIDO device name={name} vid={vendor:#06x} pid={product:#06x}"
        );
        Ok(device)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn send_input(&mut self, report: &[u8]) -> Result<()> {
        if report.len() > HID_REPORT_SIZE {
            bail!("report too large: {}", report.len());
        }
        let mut input = UhidInput2 {
            size: report.len() as u16,
            data: [0; 4096],
        };
        input.data[..report.len()].copy_from_slice(report);

        let mut buf = vec![0u8; 4 + std::mem::size_of::<UhidInput2>()];
        buf[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&input as *const UhidInput2) as *const u8,
                std::mem::size_of::<UhidInput2>(),
            )
        };
        buf[4..].copy_from_slice(bytes);
        self.file.write_all(&buf).context("UHID_INPUT2")?;
        debug!("uhid input {} bytes", report.len());
        Ok(())
    }

    /// Read the next event. Returns Some(report) for UHID_OUTPUT, None for other events.
    pub fn read_event(&mut self) -> Result<Option<[u8; HID_REPORT_SIZE]>> {
        // uhid_event is type (4) + large union (~4376)
        let mut buf = vec![0u8; 8 + 4096 + 16];
        let n = match self.file.read(&mut buf) {
            Ok(0) => return Ok(None),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e).context("read uhid"),
        };
        if n < 4 {
            return Ok(None);
        }
        let etype = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        match etype {
            6 => {
                // UHID_OUTPUT
                // After type: data[4096], size u16, rtype u8
                if n < 4 + 4096 + 2 {
                    // Try compact parse: some kernels write only used portion.
                }
                let size = if n >= 4 + 4096 + 2 {
                    u16::from_ne_bytes(buf[4 + 4096..4 + 4096 + 2].try_into().unwrap()) as usize
                } else if n >= 6 {
                    // Fallback: assume size at end of short read is wrong; use HID size
                    HID_REPORT_SIZE.min(n - 4)
                } else {
                    return Ok(None);
                };
                let size = size.min(HID_REPORT_SIZE).min(n.saturating_sub(4));
                let mut report = [0u8; HID_REPORT_SIZE];
                let copy_len = size.min(HID_REPORT_SIZE);
                report[..copy_len].copy_from_slice(&buf[4..4 + copy_len]);
                debug!("uhid output {copy_len} bytes etype={etype}");
                Ok(Some(report))
            }
            2 => {
                debug!("uhid START");
                Ok(None)
            }
            3 => {
                debug!("uhid STOP");
                Ok(None)
            }
            4 => {
                debug!("uhid OPEN");
                Ok(None)
            }
            5 => {
                debug!("uhid CLOSE");
                Ok(None)
            }
            other => {
                debug!("uhid event {other}");
                Ok(None)
            }
        }
    }

    pub fn destroy(&mut self) -> Result<()> {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&UHID_DESTROY.to_ne_bytes());
        let _ = self.file.write_all(&buf);
        Ok(())
    }
}

impl Drop for UhidDevice {
    fn drop(&mut self) {
        let _ = self.destroy();
    }
}

fn copy_cstr(dst: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len().saturating_sub(1));
    dst[..n].copy_from_slice(&bytes[..n]);
    dst[n] = 0;
}

fn libc_nonblock() -> i32 {
    libc::O_NONBLOCK
}

// Minimal libc constants without depending on full nix for open flags
mod libc {
    pub const O_NONBLOCK: i32 = 0x800;
}
