#[macro_use]
extern crate nom;

use nom::{error::ErrorKind, Err};

mod parsers;

#[derive(Debug, Clone, PartialEq)]
pub struct Quote<'a> {
    pub header: Header<'a>,
    pub isv_report: ReportBody<'a>,
    pub signature: Signature<'a>,
    signed_message: &'a [u8],
}

impl<'a> Quote<'a> {
    pub fn parse(quote_bytes: &'a [u8]) -> Result<Self, Err<(&'a [u8], ErrorKind)>> {
        crate::parsers::parse_quote(quote_bytes).map(|qp| qp.1)
    }
}

impl<'a> AsRef<[u8]> for Quote<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.signed_message
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header<'a> {
    pub version: u16,
    pub qe_svn: u16,
    pub pce_svn: u16,
    pub qe_vendor_id: &'a [u8],
    pub user_data: &'a [u8],
}

#[derive(Debug, Clone, PartialEq)]
pub enum Signature<'a> {
    EcdsaP256 {
        isv_report_signature: &'a [u8],
        attestation_key: &'a [u8],
        qe_report: ReportBody<'a>,
        qe_report_signature: &'a [u8],
        qe_authentication_data: &'a [u8],
        qe_certification_data: QeCertificationData<'a>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReportBody<'a> {
    pub cpu_svn: &'a [u8],
    pub miscselect: u32,
    pub attributes: &'a [u8],
    pub mrenclave: &'a [u8],
    pub mrsigner: &'a [u8],
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub report_data: &'a [u8],
    signed_message: &'a [u8],
}

impl<'a> ReportBody<'a> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.signed_message
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum QeCertificationData<'a> {
    Ppid {
        ppid: Ppid<'a>,
        cpu_svn: &'a [u8],
        pce_svn: u16,
        pce_id: u16,
    },
    CertChain(&'a [u8]),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Ppid<'a> {
    Clear(&'a [u8]),
    Enc2048(&'a [u8]),
    Enc3072(&'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::*;

    static V2_QUOTE: &[u8] = include_bytes!("../fixtures/v2_quote.bin");

    #[test]
    fn test_parse_v2_quote() {
        assert!(Quote::parse(V2_QUOTE).is_ok());
    }
}
