use nom::bytes::streaming::take;
use nom::combinator::map;
use nom::multi::length_data;
use nom::number::streaming::{be_u16, be_u8};
use nom::IResult;
use std::borrow::Cow;

pub(crate) fn length_data_cow_u8(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    map(length_data(be_u8), Cow::Borrowed)(i)
}

pub(crate) fn length_data_cow_u16(i: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    map(length_data(be_u16), Cow::Borrowed)(i)
}

pub(crate) fn take_cow<USZ: Copy + Into<usize>>(
    n: USZ,
) -> impl FnMut(&[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
    move |i| map(take(n.into()), Cow::Borrowed)(i)
}
