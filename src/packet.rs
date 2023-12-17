use crate::byte_packet_buffer::BytePacketBuffer;
use crate::header::Header;
use crate::question::Question;
use crate::record::Record;

#[derive(Clone, Debug, Default)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
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

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> anyhow::Result<()> {
        self.header.question_count = self.questions.len() as u16;
        self.header.answer_count = self.answers.len() as u16;
        self.header.authority_count = 0;
        self.header.additional_count = 0;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Opcode, RCode};
    use crate::question::{QClass, QType};
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_packet() {
        let packet = Packet::default();
        assert_eq!(packet.header, Header::default());
        assert_eq!(packet.questions, Vec::default());
        assert_eq!(packet.answers, Vec::default());
    }

    #[test]
    fn test_default_packet_header_bytes() {
        let mut buffer = BytePacketBuffer::new();
        let mut packet = Packet::default();
        packet.write(&mut buffer).unwrap();
        assert_eq!(
            buffer.buf[..buffer.pos],
            [4, 210, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0,]
        );
    }

    fn build_standard_packet_bytes() -> [u8; 64] {
        [
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
        ]
    }

    #[test]
    fn test_standard_packet_from_bytes() {
        let mut bytes = build_standard_packet_bytes();
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

        let mut buffer = BytePacketBuffer::new();
        let mut packet = packet;
        packet.write(&mut buffer).unwrap();
        assert_eq!(
            buffer.buf[..buffer.pos],
            [
                4, 210, 128, 0, 0, 1, 0, 1, 0, 0, 0, 0, 12, 99, 111, 100, 101, 99, 114, 97, 102,
                116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 12, 99, 111, 100, 101, 99, 114, 97,
                102, 116, 101, 114, 115, 2, 105, 111, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 8, 8, 8, 8
            ]
        );
    }
}
