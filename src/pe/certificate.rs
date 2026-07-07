//! Authenticode certificate table (`IMAGE_DIRECTORY_ENTRY_SECURITY`).

use crate::errors::FileParseError;
use crate::field::Field;
use crate::utils::{extract_u16, extract_u32};

/// `WIN_CERT_REVISION_2_0`.
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA`.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// `WIN_CERTIFICATE` header (variable-length PKCS#7 blob follows).
pub struct WinCertificate {
    /// Total length of the certificate entry, including this header (`dwLength`).
    pub length: Field<u32>,
    /// Certificate revision (`wRevision`).
    pub revision: Field<u16>,
    /// Certificate type (`wCertificateType`).
    pub certificate_type: Field<u16>,
    /// Absolute file offset of the first certificate data byte.
    pub data_offset: usize,
}

/// Read-only view of the certificate table overlay.
pub struct CertificateTable {
    /// File offset of the first `WIN_CERTIFICATE` (`IMAGE_DIRECTORY_ENTRY_SECURITY` uses a file offset, not an RVA).
    pub offset: usize,
    /// Total size in bytes from the data directory entry.
    pub size: usize,
    /// Parsed certificate headers chained in file order.
    pub certificates: Vec<WinCertificate>,
}

impl WinCertificate {
    /// Minimum header size before certificate data.
    pub const HEADER_SIZE: usize = 8;

    /// Parses one `WIN_CERTIFICATE` at `offset`.
    pub fn parse(buffer: &[u8], offset: usize) -> Result<Self, FileParseError> {
        if buffer.len() < offset + Self::HEADER_SIZE {
            return Err(FileParseError::BufferOverflow);
        }

        let length = extract_u32(buffer, offset)?;
        if length < Self::HEADER_SIZE as u32 {
            return Err(FileParseError::InvalidFileFormat);
        }

        Ok(WinCertificate {
            length: Field::new(length, offset, 4),
            revision: Field::new(extract_u16(buffer, offset + 4)?, offset + 4, 2),
            certificate_type: Field::new(extract_u16(buffer, offset + 6)?, offset + 6, 2),
            data_offset: offset + Self::HEADER_SIZE,
        })
    }

    /// Returns the PKCS#7 / certificate payload bytes.
    pub fn data<'a>(&self, buffer: &'a [u8]) -> Result<&'a [u8], FileParseError> {
        let end = self
            .length
            .offset
            .checked_add(self.length.value as usize)
            .ok_or(FileParseError::BufferOverflow)?;
        buffer
            .get(self.data_offset..end)
            .ok_or(FileParseError::BufferOverflow)
    }
}

impl CertificateTable {
    /// Parses the certificate table at `file_offset` with total `size`.
    ///
    /// `file_offset` and `size` come from `IMAGE_DIRECTORY_ENTRY_SECURITY` (file offsets, not RVAs).
    pub fn parse(buffer: &[u8], file_offset: u32, size: u32) -> Result<Self, FileParseError> {
        if file_offset == 0 || size == 0 {
            return Ok(CertificateTable {
                offset: 0,
                size: 0,
                certificates: Vec::new(),
            });
        }

        let offset = file_offset as usize;
        let total = size as usize;
        let end = offset
            .checked_add(total)
            .ok_or(FileParseError::BufferOverflow)?;
        if buffer.len() < end {
            return Err(FileParseError::BufferOverflow);
        }

        let mut certificates = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            let cert = WinCertificate::parse(buffer, cursor)?;
            let aligned = align_up(cert.length.value as usize, 8);
            if aligned == 0 {
                return Err(FileParseError::InvalidFileFormat);
            }
            certificates.push(cert);
            cursor = cursor
                .checked_add(aligned)
                .ok_or(FileParseError::BufferOverflow)?;
        }

        Ok(CertificateTable {
            offset,
            size: total,
            certificates,
        })
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}
