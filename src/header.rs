use crate::byte_packet_buffer::BytePacketBuffer;

//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that generates any kind of query.
    /// This identifier is copied the corresponding reply and can be used by the requester to match up replies to outstanding queries.
    /// bits = 0..=15, big endian
    pub id: u16,
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    /// bits = 16
    pub is_reply: bool,
    /// A four bit field that specifies kind of query in this message.
    /// This value is set by the originator of a query and copied into the response.
    /// bits = 17..=20
    pub opcode: Opcode,
    /// Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section.
    ///
    /// Note that the contents of the answer section may have multiple owner names because of aliases.
    /// The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
    /// bits = 21
    pub authoritative: bool,
    /// Truncation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
    /// 1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    /// bits = 22
    pub truncation: bool,
    /// Recursion Desired - this bit may be set in a query an is copied into the response.
    /// If RD is set, it directs the name server to pursue the query recursively.
    /// Recursive query support is optional.
    /// bits = 23
    pub recursion_desired: bool,
    /// Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
    /// bits = 24
    pub recursion_available: bool,
    // Reserved (Z) 	3 bits 	Used by DNSSEC queries. At inception, it was reserved for future use.
    // 25..=27
    /// Response code - this 4 bit field is set as part of responses.
    /// bits = 25..=31
    pub rcode: RCode,
    /// an unsigned 16 bit integer specifying the number of entries in the question section.
    /// bits = 32..=47, big endian
    pub question_count: u16,
    /// an unsigned 16 bit integer specifying the number of resource records in the answer section.
    /// bits = 48..=63, big endian
    pub answer_count: u16,
    /// an unsigned 16 bit integer specifying the number of name server resource records in the authority records section
    /// bits = 64..=79, big endian
    pub authority_count: u16,
    /// an unsigned 16 bit integer specifying the number of resource records in the additional records section.
    /// bits = 80..=95, big endian
    pub additional_count: u16,
}

/// A four bit field that specifies kind of query in this message.
/// This value is set by the originator of a query and copied into the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// a standard query
    QUERY = 0,
    /// an inverse query
    IQUERY = 1,
    /// a server status request
    STATUS = 2,
    //3-15 reserved for future use
}

/// Response code - this 4 bit field is set as part of responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RCode {
    /// No error condition
    NoError = 0,
    /// The name server was unable to interpret the query.
    FormatError = 1,
    /// The name server was unable to process this query due to a problem with the name server.
    ServerFailure = 2,
    /// Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// The name server refuses to perform the specified operation for policy reasons.
    /// For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
    Refused = 5,
    // 6-15 Reserved for future use.
}

impl From<u8> for Opcode {
    fn from(byte: u8) -> Self {
        match byte {
            0 => Opcode::QUERY,
            1 => Opcode::IQUERY,
            2 => Opcode::STATUS,
            _ => panic!("Invalid opcode"),
        }
    }
}

impl From<u8> for RCode {
    fn from(byte: u8) -> Self {
        match byte {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            _ => panic!("Invalid rcode"),
        }
    }
}

impl Default for Header {
    fn default() -> Self {
        Self {
            id: 1234,
            is_reply: true,
            opcode: Opcode::QUERY,
            authoritative: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            rcode: RCode::NoError,
            question_count: 0,
            answer_count: 0,
            authority_count: 0,
            additional_count: 0,
        }
    }
}

impl Header {
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncation = (a & (1 << 1)) > 0;
        self.authoritative = (a & (1 << 2)) > 0;
        self.opcode = ((a >> 3) & 0x0F).into();
        self.is_reply = (a & (1 << 7)) > 0;

        self.rcode = (b & 0x0F).into();
        self.recursion_available = (b & (1 << 7)) > 0;

        self.question_count = buffer.read_u16()?;
        self.answer_count = buffer.read_u16()?;
        self.authority_count = buffer.read_u16()?;
        self.additional_count = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncation as u8) << 1)
                | ((self.authoritative as u8) << 2)
                | ((self.opcode as u8) << 3)
                | ((self.is_reply as u8) << 7),
        )?;

        buffer.write_u8((self.rcode as u8) | ((self.recursion_available as u8) << 7))?;

        buffer.write_u16(self.question_count)?;
        buffer.write_u16(self.answer_count)?;
        buffer.write_u16(self.authority_count)?;
        buffer.write_u16(self.additional_count)?;

        Ok(())
    }
}
