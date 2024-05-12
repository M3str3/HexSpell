use crate::field::Field;

#[derive(PartialEq, Eq, Debug)]
pub enum PEType {
    PE32,
    PE32Plus,
}

pub enum ImageBase {
    Base32(u32),
    Base64(u64),
}

pub enum Architecture {
    X86,
    X64,
    Unknown,
}

impl Architecture {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x014c => Architecture::X86,
            0x8664 => Architecture::X64,
            _ => Architecture::Unknown,
        }
    }

    pub fn to_string(&self) -> String {
        match *self {
            Architecture::X86 => "x86".to_string(),
            Architecture::X64 => "x64".to_string(),
            Architecture::Unknown => "Unknown".to_string(),
        }
    }
}

pub struct PeHeader {
    pub architecture: Field<String>,         // Architecture type, e.g., x86, x64
    pub entry_point: Field<u32>,             // Relative virtual address (RVA) of the entry point of the executable
    pub size_of_image: Field<u32>,           // Total size of the image loaded in memory
    pub number_of_sections: Field<u16>,      // Number of sections in the file
    pub checksum: Field<u32>,                // Checksum of the image
    pub section_alignment: Field<u32>,       // Alignment of sections when loaded into memory
    pub file_alignment: Field<u32>,          // Alignment factor that is used to align the raw data of sections in the image file
    pub size_of_headers: Field<u32>,         // Combined size of all headers
    pub base_of_code: Field<u32>,            // RVA of the code section
    pub base_of_data: Field<u32>,            // RVA of the data section
    pub image_base: Field<ImageBase>,        // Preferred base address of the image when loaded into memory
    pub subsystem: Field<u16>,               // Subsystem required to run this image, e.g., GUI or console
    pub dll_characteristics: Field<u16>,     // DLL characteristics flags
    pub pe_type: PEType,                     // Type of the PE file, e.g., PE32 or PE32+
}

