use crate::byte_packet_buffer::BytePacketBuffer;
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: QType,
    pub qclass: QClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    /// a host address
    A = 1,
    /// an authoritative name server
    NS = 2,
    /// a mail destination (Obsolete - use MX)
    MD = 3,
    /// a mail forwarder (Obsolete - use MX)
    MF = 4,
    /// the canonical name for an alias
    CNAME = 5,
    /// marks the start of a zone of authority
    SOA = 6,
    /// a mailbox domain name (EXPERIMENTAL)
    MB = 7,
    /// a mail group member (EXPERIMENTAL)
    MG = 8,
    /// a mail rename domain name (EXPERIMENTAL)
    MR = 9,
    /// a null RR (EXPERIMENTAL)
    NULL = 10,
    /// a well known service description
    WKS = 11,
    /// a domain name pointer
    PTR = 12,
    /// host information
    HINFO = 13,
    /// mailbox or mail list information
    MINFO = 14,
    /// mail exchange
    MX = 15,
    /// text strings
    TXT = 16,

    // QTYPE specific
    /// A request for a transfer of an entire zone
    AXFR = 252,
    /// A request for mailbox-related records (MB, MG or MR)
    MAILB = 253,
    ///  A request for mail agent RRs (Obsolete - see MX)
    MAILA = 254,
    /// A request for all records
    ANY = 255,
}

impl From<u16> for QType {
    fn from(byte: u16) -> Self {
        match byte {
            1 => QType::A,
            2 => QType::NS,
            3 => QType::MD,
            4 => QType::MF,
            5 => QType::CNAME,
            6 => QType::SOA,
            7 => QType::MB,
            8 => QType::MG,
            9 => QType::MR,
            10 => QType::NULL,
            11 => QType::WKS,
            12 => QType::PTR,
            13 => QType::HINFO,
            14 => QType::MINFO,
            15 => QType::MX,
            16 => QType::TXT,
            252 => QType::AXFR,
            253 => QType::MAILB,
            254 => QType::MAILA,
            255 => QType::ANY,
            _ => panic!("Invalid qtype"),
        }
    }
}

impl From<u16> for QClass {
    fn from(byte: u16) -> Self {
        match byte {
            1 => QClass::IN,
            2 => QClass::CS,
            3 => QClass::CH,
            4 => QClass::HS,
            255 => QClass::Any,
            _ => panic!("Invalid qclass"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QClass {
    /// the Internet
    IN = 1,
    /// the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CS = 2,
    /// the CHAOS class
    CH = 3,
    /// Hesiod [Dyer 87]
    HS = 4,
    // QCLASS specific
    /// any class
    Any = 255,
}

impl Default for Question {
    fn default() -> Self {
        Self {
            name: String::new(),
            qtype: QType::A,
            qclass: QClass::IN,
        }
    }
}

impl Question {
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = buffer.read_u16()?.into();
        self.qclass = buffer.read_u16()?.into();

        Ok(())
    }
}
