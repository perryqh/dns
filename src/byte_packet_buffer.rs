pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl BytePacketBuffer {
    /// This gives us a fresh buffer for holding the packet contents, and a
    /// field for keeping track of where we are.
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    /// Current position within buffer
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    pub fn step(&mut self, steps: usize) -> anyhow::Result<()> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    pub fn seek(&mut self, pos: usize) -> anyhow::Result<()> {
        self.pos = pos;

        Ok(())
    }

    /// Read a single byte and move the position one step forward
    pub fn read(&mut self) -> anyhow::Result<u8> {
        if self.pos >= 512 {
            anyhow::bail!("End of buffer");
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    /// Get a single byte, without changing the buffer position
    pub fn get(&mut self, pos: usize) -> anyhow::Result<u8> {
        if pos >= 512 {
            anyhow::bail!("End of buffer");
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    pub fn get_range(&mut self, start: usize, len: usize) -> anyhow::Result<&[u8]> {
        if start + len >= 512 {
            anyhow::bail!("End of buffer");
        }
        Ok(&self.buf[start..start + len])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> anyhow::Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> anyhow::Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    /// Read a qname
    pub fn read_qname(&mut self, outstr: &mut String) -> anyhow::Result<()> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                anyhow::bail!("Limit of {} jumps exceeded", max_jumps);
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }

    pub fn write(&mut self, val: u8) -> anyhow::Result<()> {
        if self.pos >= 512 {
            anyhow::bail!("End of buffer");
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> anyhow::Result<()> {
        self.write(val)?;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> anyhow::Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> anyhow::Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> anyhow::Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x3f {
                anyhow::bail!("Single label exceeds 63 characters of length");
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_u16() {
        let mut packet = BytePacketBuffer::new();
        packet.write_u16(0x1234).unwrap();
        assert_eq!(packet.pos(), 2);
        assert_eq!(packet.buf[0], 0x12);
        assert_eq!(packet.buf[1], 0x34);

        packet.seek(0).unwrap();
        let res = packet.read_u16().unwrap();
        assert_eq!(res, 0x1234);
        assert_eq!(packet.pos(), 2);
    }

    #[test]
    fn test_read_write_u32() {
        let mut packet = BytePacketBuffer::new();
        packet.write_u32(0x12345678).unwrap();
        assert_eq!(packet.pos(), 4);
        assert_eq!(packet.buf[0], 0x12);
        assert_eq!(packet.buf[1], 0x34);
        assert_eq!(packet.buf[2], 0x56);
        assert_eq!(packet.buf[3], 0x78);

        packet.seek(0).unwrap();
        let res = packet.read_u32().unwrap();
        assert_eq!(res, 0x12345678);
        assert_eq!(packet.pos(), 4);
    }

    #[test]
    fn test_read_write_qname() {
        let mut packet = BytePacketBuffer::new();
        packet.write_qname("www").unwrap();
        assert_eq!(packet.pos(), 5);
        assert_eq!(packet.buf[0], 3);
        assert_eq!(packet.buf[1], b'w');
        assert_eq!(packet.buf[2], b'w');
        assert_eq!(packet.buf[3], b'w');
        assert_eq!(packet.buf[4], 0);

        let mut packet = BytePacketBuffer::new();
        packet.write_qname("www.google.com").unwrap();
        assert_eq!(packet.pos(), 16);
        assert_eq!(packet.buf[0], 3);
        assert_eq!(packet.buf[1..=3], [b'w', b'w', b'w']);
        assert_eq!(packet.buf[4], 6);
        assert_eq!(packet.buf[5..=10], [b'g', b'o', b'o', b'g', b'l', b'e']);
        assert_eq!(packet.buf[11], 3);
        assert_eq!(packet.buf[12..=14], [b'c', b'o', b'm']);
        assert_eq!(packet.buf[15], 0);

        packet.seek(0).unwrap();
        let mut outstr = String::new();
        packet.read_qname(&mut outstr).unwrap();
        assert_eq!(outstr, "www.google.com");
    }

    #[test]
    fn test_read_compressed_qname() {
        let mut packet = BytePacketBuffer::new();
        packet.write_qname("f.isi.arpa").unwrap();
        let pos = packet.pos();
        packet.write_u8(0x03 << 6).unwrap();
        packet.write_u8(0).unwrap();

        packet.seek(pos).unwrap();
        let mut outstr = String::new();
        packet.read_qname(&mut outstr).unwrap();
        assert_eq!(outstr, "f.isi.arpa");
    }

    #[test]
    fn test_read_compressed_partial_qname() {
        let mut packet = BytePacketBuffer::new();
        packet.write_qname("f.isi.arpa").unwrap();
        let pos = packet.pos();
        packet.write_u8(3).unwrap();
        packet.write_u8(b'f').unwrap();
        packet.write_u8(b'o').unwrap();
        packet.write_u8(b'o').unwrap();
        packet.write_u8(0x03 << 6).unwrap();
        packet.write_u8(2).unwrap();

        packet.seek(pos).unwrap();
        let mut outstr = String::new();
        packet.read_qname(&mut outstr).unwrap();
        assert_eq!(outstr, "foo.isi.arpa");
    }
}
