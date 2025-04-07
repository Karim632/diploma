use std::{error::Error, fmt::{self, Display, Formatter}};

#[derive(Debug, Clone)]
pub struct MalformedModifiedUtf8 {
    msg: String,
}

impl Display for MalformedModifiedUtf8 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Napaka v modified UTF-8: {}." , self.msg)
    }
}

impl Error for MalformedModifiedUtf8 {}

impl MalformedModifiedUtf8 {
    pub fn invalid_codepoint(codepoint: u32, byte_1_index: usize) -> MalformedModifiedUtf8 {
        return MalformedModifiedUtf8{ msg: format!("neveljaven codepoint od bajta {} naprej: {:#0x}", byte_1_index, codepoint) };
    }

    pub fn unexpected_last_byte(byte: u8) -> MalformedModifiedUtf8 {
        return MalformedModifiedUtf8{ msg: format!("bajt {:#0x} ne more biti zadnji", byte) };
    }
}

/** https://docs.oracle.com/javase/specs/jvms/se22/html/jvms-4.html#jvms-4.4.7 */
pub fn modified_utf8_to_string(bytes: &Vec<u8>) -> Result<String, MalformedModifiedUtf8> {
    let mut converted: Vec<char> = vec![];
    let mut i: usize = 0;
    while i < bytes.len() {
        let byte_1 = bytes[i];
        if byte_1 == 0 || (byte_1 >= 0xF0) {
            return Err(MalformedModifiedUtf8{ msg: format!("bajt {} je enak 0 oz. je med 0xF0 in 0xFF", i) });
        }
        else if byte_1 <= 0x7F {
            converted.push(char::from_u32(byte_1.into()).ok_or(MalformedModifiedUtf8::invalid_codepoint(byte_1.into(), i))?);
        }
        else if i + 1 >= bytes.len() {
            return Err(MalformedModifiedUtf8 { msg: format!("bajt {:#0x} ne more biti zadnji", byte_1) });
        }
        else {
            i += 1;
            let byte_2 = bytes[i];
            let code_point;
            if byte_1 & 0b1110_0000 == 0b1100_0000 {
                code_point = ((byte_1 as u32 & 0x1F) << 6) + (byte_2 as u32 & 0x3F);
            }
            else if i + 1 >= bytes.len() {
                return Err(MalformedModifiedUtf8 { msg: format!("bajta {:#0x} in {:#0x} ne moreta biti zadnja", byte_1, byte_2) });
            }
            else {
                i += 1;
                let byte_3 = bytes[i];
                if byte_1 & 0b1111_0000 == 0b1110_0000 {
                    code_point = ((byte_1 as u32 & 0xF) << 12) + ((byte_2 as u32 & 0x3F) << 6) + (byte_3 as u32 & 0x3F);
                }
                else if i + 3 >= bytes.len() {
                    return Err(MalformedModifiedUtf8 { msg: format!("po bajtih {:#0x}, {:#0x} in {:#0x} so pričakovani še 3 bajti, obstaja pa jih {}", byte_1, byte_2, byte_3, bytes.len() - i + 1) });
                }
                else {
                    // let byte_4 = bytes[i + 1]; // se ne uporablja
                    let byte_5 = bytes[i + 2];
                    let byte_6 = bytes[i + 3];
                    i += 3;
                    code_point = 0x10000 + ((byte_2 as u32 & 0x0F) << 16) + ((byte_3 as u32 & 0x3F) << 10) +
                    ((byte_5 as u32 & 0x0F) << 6) + (byte_6 as u32 & 0x3F);
                }
            }

            converted.push(char::from_u32(code_point).ok_or(MalformedModifiedUtf8::invalid_codepoint(byte_1.into(), i))?);
        }

        i += 1;
    }

    return Ok(String::from_iter(converted));
}
