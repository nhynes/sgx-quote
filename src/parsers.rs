use nom::{
    error::ErrorKind,
    number::complete::{le_u16, le_u32},
    take, IResult,
};

use crate::*;

pub const HEADER_SIZE: usize = 48;
pub const REPORT_SIZE: usize = 384;

#[rustfmt::skip]
pub(crate) fn parse_quote(i: &[u8]) -> IResult<&[u8], Quote, (&[u8], ErrorKind)> {
    do_parse!(
        i,
        header_ext: parse_header_ext                  >>
        isv_report: parse_report_body                 >>
        signature:  length_value!(le_u32,
            call!(parse_signature, header_ext.ak_ty)) >>
        _eof:       eof!()                            >>
        (
            Quote {
                header: header_ext.header,
                isv_report,
                signature,
                signed_message: &i[..(HEADER_SIZE + REPORT_SIZE)],
            }
        )
    )
}

struct HeaderExt<'a> {
    header: Header<'a>,
    ak_ty: u16,
}

named! {
    parse_header_ext<HeaderExt>,
    do_parse!(
        version:              le_u16    >>
        attestation_key_type: le_u16    >>
        _reserved_1:          take!(4)  >>
        qe_svn:               le_u16    >>
        pce_svn:              le_u16    >>
        qe_vendor_id:         take!(16) >>
        user_data:            take!(20) >>
        (
            HeaderExt {
                header: Header {
                    version,
                    qe_svn,
                    pce_svn,
                    qe_vendor_id,
                    user_data
                },
                ak_ty: attestation_key_type,
            }
        )
    )
}

#[rustfmt::skip]
fn parse_report_body(i: &[u8]) -> IResult<&[u8], ReportBody, (&[u8], ErrorKind)> {
    do_parse!(
        i,
        cpu_svn:     take!(16) >>
        miscselect:  le_u32    >>
        _reserved_1: take!(28) >>
        attributes:  take!(16) >>
        mrenclave:   take!(32) >>
        _reserved_2: take!(32) >>
        mrsigner:    take!(32) >>
        _reserved_3: take!(96) >>
        isv_prod_id: le_u16    >>
        isv_svn:     le_u16    >>
        _reserved_4: take!(60) >>
        report_data: take!(64) >>
        (
            ReportBody {
                cpu_svn,
                miscselect,
                attributes,
                mrenclave,
                mrsigner,
                isv_prod_id,
                isv_svn,
                report_data,
                signed_message: &i[..REPORT_SIZE]
            }
        )
    )
}

named_args! {
    parse_signature(_attestation_key_type: u16)<Signature>,
    do_parse!(
        isv_report_signature:       take!(64)                         >>
        attestation_key:            take!(64)                         >>
        qe_report:                  parse_report_body                 >>
        qe_report_signature:        take!(64)                         >>
        qe_authentication_data:     length_data!(le_u16)              >>
        qe_certification_data_type: verify!(le_u16, is_valid_cd_type) >>
        qe_certification_data:      length_value!(le_u32,
            call!(parse_qe_cd, qe_certification_data_type))           >>
        (
            Signature::EcdsaP256 {
                isv_report_signature,
                attestation_key,
                qe_report,
                qe_report_signature,
                qe_authentication_data,
                qe_certification_data,
            }
        )
    )
}

#[allow(clippy::trivially_copy_pass_by_ref)] // The macro inserts a ref and rustc won't deref it.
fn is_valid_cd_type(t: &u16) -> bool {
    *t >= 1 && *t <= 5 && *t != 4
}

#[rustfmt::skip]
macro_rules! parse_ppid_cd {
    ($i:expr, $kind:expr) => {
        do_parse!(
            $i,
            ppid:    map!(take!(384), $kind) >>
            cpu_svn: take!(16)               >>
            pce_svn: le_u16                  >>
            pce_id:  le_u16                  >>
            (
                QeCertificationData::Ppid {
                    ppid,
                    cpu_svn,
                    pce_svn,
                    pce_id
                }
            )
        )
    };
}

fn parse_qe_cd(i: &[u8], kind: u16) -> IResult<&[u8], QeCertificationData, (&[u8], ErrorKind)> {
    match kind {
        1 => parse_ppid_cd!(i, Ppid::Clear),
        2 => parse_ppid_cd!(i, Ppid::Enc2048),
        3 => parse_ppid_cd!(i, Ppid::Enc3072),
        5 => Ok((&[], QeCertificationData::CertChain(i))),
        _ => unreachable!(),
    }
}
