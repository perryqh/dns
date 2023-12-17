use crate::byte_packet_buffer::BytePacketBuffer;
use crate::header::Header;
use crate::question::Question;
use crate::record::Record;

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            header: Header::default(),
            questions: Vec::default(),
            answers: Vec::default(),
        }
    }
}

impl Packet {
    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> anyhow::Result<Packet> {
        let mut result = Packet::default();
        result.header.read(buffer)?;

        for _ in 0..result.header.question_count {
            let mut question = Question::default();
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answer_count {
            let rec = Record::read(buffer)?;
            result.answers.push(rec);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use super::*;
    use crate::header::{Opcode, RCode};
    use crate::question::{QClass, QType};

    #[test]
    fn default_packet() {
        let packet = Packet::default();
        assert_eq!(packet.header, Header::default());
        assert_eq!(packet.questions, Vec::default());
        assert_eq!(packet.answers, Vec::default());
    }

    // #[test]
    // fn default_packet_bytes() {
    //     let packet = Packet::default();
    //     let bytes = packet.as_bytes();
    //     assert_eq!(
    //         bytes,
    //         [
    //             4, 210, 128, 0, 0, 1, 0, 1, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102,
    //             116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 12, 99, 111, 100, 101, 99, 114, 97,
    //             102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8
    //         ]
    //     );
    // }

    #[test]
    fn packet_from_bytes() {
        let mut bytes = [
            4, 210, 128, 0, 0, 1, 0, 1, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102,
            116, // 22
            101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 12, 99, 111, 100, 101, 99, 114, 97,
            102, // rr name
            116, 101, 114, 115, 2, 105, 111, // rr name end
            0,   // terminate rrname
            0, 1, // rr type
            0, 1, // rr class
            0, 0, 0, 60, // ttl
            0, 4, // rdlength
            8, 8, 8, 8, // rdata
        ];
        let mut buffer = BytePacketBuffer::new();
        buffer.buf[..bytes.len()].copy_from_slice(&mut bytes);

        let packet = Packet::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.header.id, 1234);
        assert_eq!(packet.header.is_reply, true);
        assert_eq!(packet.header.opcode, Opcode::QUERY);
        assert_eq!(packet.header.authoritative, false);
        assert_eq!(packet.header.truncation, false);
        assert_eq!(packet.header.recursion_desired, false);
        assert_eq!(packet.header.recursion_available, false);
        assert_eq!(packet.header.rcode, RCode::NoError);
        assert_eq!(packet.header.question_count, 1);
        assert_eq!(packet.header.answer_count, 1);
        assert_eq!(packet.header.authority_count, 0);
        assert_eq!(packet.header.additional_count, 0);
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].name, "codecrafters.io");
        assert_eq!(packet.questions[0].qtype, QType::A);
        assert_eq!(packet.questions[0].qclass, QClass::IN);
        match &packet.answers[0] {
            Record::A { domain, addr, ttl } => {
                assert_eq!(domain, "codecrafters.io");
                assert_eq!(addr, &Ipv4Addr::new(8, 8, 8, 8));
                assert_eq!(ttl, &60);
            }
            _ => panic!("Wrong record type"),
        }
    }

    // The compression scheme allows a domain name in a message to be
    // represented as either:
    //
    //    - a sequence of labels ending in a zero octet
    //
    //    - a pointer
    //
    //    - a sequence of labels ending with a pointer
    // #[test]
    // fn test_message_with_compression() {
    //     let q: = [1, b"F", 3, b"I", b"S", b"I", 4, b"A", b"R", b"P", b"A"]
    //     let bytes = [
    //         4, 210, 128, 0, 0, 1, 0, 0, 0, 0, 0, 0, // end of header (12 bytes)
    //         1, b"F", 3, b"I", b"S", b"I", // 18
    //         4, b"A", b"R", b"P", b"A",
    //         0, // terminate first label sequence
    //         3, b"F", b"O", b"0",
    //         1, 1, 13, // pointer 13 byte TODO: somehow the offset is 14 bits
    //         1, 1, 19, // TODO: 14 bits?
    //         0, // terminate last label
    //         0,1, // qtype
    //         0,1, // qclass
    //     ];
    //     let message = Message::from_bytes(&bytes);
    //     assert_eq!(
    //         message.questions[0].qname,
    //         vec![b"codecrafters".to_vec(), b"io".to_vec()]
    //     );
    // }
}
