use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use curve25519_dalek::scalar::Scalar;
use digest::Digest;
use generic_array::{ArrayLength, GenericArray};
use rand_core::{CryptoRng, RngCore};
use rand_os::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::error;
use std::fmt;
use std::io::{Cursor, Read};
use std::ops::{Index, IndexMut};
use std::result;
use typenum::consts::U256;

/// `ErrorKind` is the type of error in `Error`.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum ErrorKind {
    Io,
    Value,
    Op,
    Node,
    Circuit,
    Other,
}

impl Default for ErrorKind {
    fn default() -> ErrorKind {
        ErrorKind::Io
    }
}

/// `Error` is the library error type.
#[derive(Debug, Default)]
pub struct Error {
    kind: ErrorKind,
    msg: String,
    source: Option<Box<dyn error::Error + 'static>>,
}

impl Error {
    /// `new` creates a new `Error`.
    pub fn new(
        kind: ErrorKind,
        msg: &str,
        source: Option<Box<dyn error::Error + 'static>>,
    ) -> Error {
        Error {
            kind,
            msg: msg.into(),
            source,
        }
    }

    /// `new_io` creates a new `Error` of type Io.
    pub fn new_io(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Io, msg, source)
    }

    /// `new_value` creates a new `Error` of type Value.
    pub fn new_value(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Value, msg, source)
    }

    /// `new_op` creates a new `Error` of type Op.
    pub fn new_op(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Op, msg, source)
    }

    /// `new_node` creates a new `Error` of type Label.
    pub fn new_node(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Node, msg, source)
    }

    /// `new_circuit` creates a new `Error` of type Circuit.
    pub fn new_circuit(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Node, msg, source)
    }

    /// `new_other` creates a new `Error` of type Other.
    pub fn new_other(msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
        Error::new(ErrorKind::Other, msg, source)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind {
            ErrorKind::Io => write!(f, "Io: {}", self.msg),
            ErrorKind::Value => write!(f, "Value: {}", self.msg),
            ErrorKind::Op => write!(f, "Op: {}", self.msg),
            ErrorKind::Node => write!(f, "Op: {}", self.msg),
            ErrorKind::Circuit => write!(f, "Op: {}", self.msg),
            ErrorKind::Other => write!(f, "Other: {}", self.msg),
        }
    }
}

/// `Result` is the type used for fallible outputs. It's an
/// alias to the Result type in standard library whith error
/// the library Error type.
pub type Result<T> = result::Result<T, Error>;

/// `random_bytes` creates a vector of random bytes.
#[allow(dead_code)]
fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut rng = OsRng::new().map_err(|e| {
        let msg = format!("{}", e);
        let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
        Error::new_io(&msg, source)
    })?;

    let res = random_bytes_from_rng(&mut rng, len);
    Ok(res)
}

/// `random_bytes_from_rng` creates a vector of random bytes using a given RNG.
pub fn random_bytes_from_rng<R>(rng: &mut R, len: usize) -> Vec<u8>
where
    R: RngCore,
{
    let mut buf = Vec::new();
    buf.resize(len, 0);

    rng.fill_bytes(&mut buf);

    let mut res = Vec::new();
    res.extend_from_slice(&buf[..]);
    res
}

/// `random_u32` returns a random `u32`.
#[allow(dead_code)]
fn random_u32() -> Result<u32> {
    let mut rng = OsRng::new().map_err(|e| {
        let msg = format!("{}", e);
        let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
        Error::new_io(&msg, source)
    })?;

    let res = random_u32_from_rng(&mut rng);
    Ok(res)
}

/// `random_u32_from_rng` returns a random `u32` using a given RNG.
pub fn random_u32_from_rng<R>(rng: &mut R) -> u32
where
    R: RngCore,
{
    rng.next_u32()
}

/// `random_bool` returns a random `bool`.
#[allow(dead_code)]
fn random_bool() -> Result<bool> {
    let mut rng = OsRng::new().map_err(|e| {
        let msg = format!("{}", e);
        let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
        Error::new_io(&msg, source)
    })?;

    let res = random_bool_from_rng(&mut rng);
    Ok(res)
}

/// `random_bool_from_rng` returns a random `bool` using a given RNG.
pub fn random_bool_from_rng<R>(rng: &mut R) -> bool
where
    R: RngCore,
{
    rng.next_u32() >= (std::u32::MAX / 2)
}

/// `extract_bit` extracts a bit from a given `u8`.
fn extract_bit(n: u8, p: usize) -> bool {
    (1 & (n >> p)) != 0
}

/// `change_bit` changes a bit of an `u8` to a given value.
fn change_bit(n: u8, p: usize, x: bool) -> u8 {
    let mask = 1 << p;
    (n & !mask) | (((x as u8) << p) & mask)
}

#[test]
fn test_extract_bit() {
    for i in 0..8 {
        let mut c = 0u8;

        c |= 1 << i;

        let c_bit = extract_bit(c, i);
        assert!(c_bit);

        c &= !(1 << i);

        let c_bit = extract_bit(c, i);
        assert!(!c_bit);
    }
}

#[test]
fn test_change_bit() {
    for i in 0..8 {
        let mut a = 0u8;
        let mut b = 255u8;

        a = change_bit(a, i, true);

        let a_bit = extract_bit(a, i);
        assert!(a_bit);

        a = change_bit(a, i, false);

        let a_bit = extract_bit(a, i);
        assert!(!a_bit);

        b = change_bit(b, i, false);

        let b_bit = extract_bit(b, i);
        assert!(!b_bit);

        b = change_bit(b, i, true);

        let b_bit = extract_bit(b, i);
        assert!(b_bit);
    }
}

/// `BitArray` is an array of bits.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct BitArray<N>(GenericArray<bool, N>)
where
    N: ArrayLength<bool>;

/// `BitArray256` is a wrapper around `BitArray<U256>`.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct BitArray256(BitArray<U256>);

impl BitArray256 {
    /// `new` creates a new `BitArray256`.
    pub fn new() -> BitArray256 {
        BitArray256::default()
    }

    /// `random` creates a new random `BitArray256`.
    pub fn random() -> Result<BitArray256> {
        let mut rng = OsRng::new().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        BitArray256::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `BitArray256` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<BitArray256>
    where
        R: RngCore,
    {
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let ba = BitArray256::from_bytes(buf);
        Ok(ba)
    }

    /// `from_bytes` creates a `BitArray256` from an array of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> BitArray256 {
        let mut ba = BitArray256::default();

        for i in 0..32 {
            for j in 0..8 {
                ba[i * 8 + j] = extract_bit(buf[i], j);
            }
        }

        ba
    }

    /// `to_bytes` converts the `BitArray256` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];

        for i in 0..32 {
            for j in 0..8 {
                buf[i] = change_bit(buf[i], j, self[i * 8 + j]);
            }
        }

        buf
    }
}

impl Index<usize> for BitArray256 {
    type Output = bool;

    fn index(&self, index: usize) -> &Self::Output {
        &(self.0).0[index]
    }
}

impl IndexMut<usize> for BitArray256 {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        (self.0).0.index_mut(index)
    }
}

#[test]
fn test_bitarray_bytes() {
    let mut rng = OsRng::new().unwrap();

    for _ in 0..10 {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);

        let ba = BitArray256::from_bytes(buf);
        let res = ba.to_bytes();
        assert_eq!(buf, res)
    }
}

/// `Value` is the a value in the field of order q = 2^255 -19.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Value(Scalar);

impl Value {
    /// `new` creates a new `Value` from a `Scalar`.
    pub fn new(s: Scalar) -> Value {
        Value(s)
    }

    /// `random` creates a new random `Value`.
    pub fn random() -> Result<Value> {
        let mut rng = OsRng::new().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let value = Value::from_rng(&mut rng);
        Ok(value)
    }

    /// `from_rng` creates a new random `Value` from a given RNG.
    pub fn from_rng<R>(mut rng: &mut R) -> Value
    where
        R: RngCore + CryptoRng,
    {
        let scalar = Scalar::random(&mut rng).reduce();
        Value(scalar)
    }

    /// `from_bytes` creates a new Value from an array of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Result<Value> {
        if let Some(scalar) = Scalar::from_canonical_bytes(buf) {
            Ok(Value(scalar))
        } else {
            let msg = "bytes are not canonical";
            let source = None;
            let err = Error::new_value(msg, source);
            Err(err)
        }
    }

    /// `to_bytes` returns the `Value` as an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `from_bitarray` creates a `Value` from a `BitArray256`.
    pub fn from_bitarray(ba: BitArray256) -> Result<Value> {
        let buf = ba.to_bytes();

        Value::from_bytes(buf)
    }

    /// `to_bitarray` converts the `Value` to a `BitArray256`.
    pub fn to_bitarray(&self) -> BitArray256 {
        let buf = self.to_bytes();
        BitArray256::from_bytes(buf)
    }
}

#[test]
fn test_value_bites() {
    for _ in 0..10 {
        let value_a = Value::random().unwrap();
        let value_bytes = value_a.to_bytes();
        let value_b = Value::from_bytes(value_bytes).unwrap();
        assert_eq!(value_a, value_b)
    }
}

#[test]
fn test_value_bitarray() {
    for _ in 0..10 {
        let value_a = Value::random().unwrap();
        let value_bitarray = value_a.to_bitarray();
        let value_b = Value::from_bitarray(value_bitarray).unwrap();
        assert_eq!(value_a, value_b)
    }
}

/// `Label` is a label of a node in the circuit.
/// NB: In the original version label is a bitarray of length l = log|C|,
/// where C is the arithmetic circuit and |C| is the length of the circuit.
/// Here instead is a fixed length of 32 bytes, the length of the output of SHA256.
/// Was it necessary to use a cryptographic hash in this context? Not per se, but
/// it would be needed in certain cases (eg: this kind of data is shared and retained
/// in some networked system).
#[derive(
    Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash, Serialize, Deserialize,
)]
pub struct Label([u8; 32]);

impl Label {
    /// `LENGHT` is the bits length of the `Label`.
    pub const LENGTH: u32 = 256;

    /// `new` creates a new `Label` for a slice of bytes as a SHA256 hash.
    pub fn new(data: &[u8]) -> Label {
        Label::from_hash(data)
    }

    /// `random` creates a new random `Label`.
    pub fn random() -> Result<Label> {
        let mut buf = [0u8; 32];
        for (i, v) in random_bytes(32)?.iter().enumerate() {
            buf[i] = *v;
        }

        let label = Label(buf);
        Ok(label)
    }

    /// `from_rng` creates a new random `Label` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<Label>
    where
        R: RngCore,
    {
        let mut buf = [0u8; 32];
        for (i, v) in random_bytes_from_rng(rng, 32).iter().enumerate() {
            buf[i] = *v;
        }

        let label = Label(buf);
        Ok(label)
    }

    /// `from_hash` creates a `Label` from a SHA256 hash of a slice of bytes.
    pub fn from_hash(data: &[u8]) -> Label {
        let mut hash = [0u8; 32];
        for (i, v) in Sha256::digest(data).as_slice().iter().enumerate() {
            hash[i] = *v;
        }
        Label(hash)
    }

    /// `from_bytes` creates a `Label` from an array of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Label {
        Label(buf)
    }

    /// `to_bytes` converts the `Label` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// `from_bitarray` creates a `Label` from a `BitArray256`.
    pub fn from_bitarray(ba: BitArray256) -> Label {
        Label(ba.to_bytes())
    }

    /// `to_bitarray` converts the `Label` to a `BitArray256`.
    pub fn to_bitarray(&self) -> BitArray256 {
        BitArray256::from_bytes(self.0)
    }

    /// `from_node_data` creates a new `Label` from `Node` fields.
    pub fn from_node_data(nonce: u32, op: &Op, value: Option<Value>) -> Result<Label> {
        let mut buf = Vec::new();

        op.validate()?;

        let nonce_buf: [u8; 4] = unsafe { std::mem::transmute::<u32, [u8; 4]>(nonce) };

        let op_buf: Vec<u8> = op.to_bytes()?;

        let value_buf = if let Some(value) = value {
            value.to_bytes()
        } else {
            [0u8; 32]
        };

        buf.extend_from_slice(&nonce_buf[..]);
        buf.extend_from_slice(&op_buf);
        buf.extend_from_slice(&value_buf[..]);

        let label = Label::new(&buf);

        Ok(label)
    }
}

#[test]
fn test_label_new() {
    for _ in 0..10 {
        let buf_a = random_bytes(32).unwrap();
        let buf_b = random_bytes(32).unwrap();
        let label_a = Label::new(&buf_a);
        let label_b = Label::new(&buf_b);

        if buf_a != buf_b {
            assert!(label_a != label_b)
        } else {
            assert_eq!(label_a, label_b)
        }
    }
}

#[test]
fn test_label_bites() {
    for _ in 0..10 {
        let label_a = Label::random().unwrap();
        let label_bytes = label_a.to_bytes();
        let label_b = Label::from_bytes(label_bytes);
        assert_eq!(label_a, label_b)
    }
}

#[test]
fn test_label_bitarray() {
    for _ in 0..10 {
        let label_a = Label::random().unwrap();
        let label_bitarray = label_a.to_bitarray();
        let label_b = Label::from_bitarray(label_bitarray);
        assert_eq!(label_a, label_b)
    }
}

/// `Op` is an arithmetic circuit operation.
#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub enum Op {
    Noop,
    Add { a: Box<Label>, b: Box<Label> },
    Mul { a: Box<Label>, b: Box<Label> },
}

impl Op {
    /// `NOOP_CODE` is the code of the Noop `Op`.
    const NOOP_CODE: u8 = 0x0;

    /// `ADD_CODE` is the code of the Add `Op`.
    const ADD_CODE: u8 = 0x1;

    /// `MUL_CODE` is the code of the Mul `Op`.
    const MUL_CODE: u8 = 0x2;

    /// `new_add` creates a new Add `Op`.
    pub fn new_add(a: &Label, b: &Label) -> Result<Op> {
        if a == b {
            let msg = "labels are not distinct";
            let source = None;
            let err = Error::new_op(msg, source);
            return Err(err);
        }

        let op = Op::Add {
            a: Box::new(a.to_owned()),
            b: Box::new(b.to_owned()),
        };

        Ok(op)
    }

    /// `random_add` creates a random Add `Op`.
    pub fn random_add() -> Result<Op> {
        let a = Label::random()?;
        let b = Label::random()?;

        Op::new_add(&a, &b)
    }

    /// `random_add_from_rng` creates a random Add `Op` from a RNG.
    pub fn random_add_from_rng<R>(rng: &mut R) -> Result<Op>
    where
        R: RngCore,
    {
        let a = Label::from_rng(rng)?;
        let b = Label::from_rng(rng)?;

        Op::new_add(&a, &b)
    }

    /// `is_add` returns if the `Op` is an Add `Op`.
    pub fn is_add(&self) -> bool {
        match self {
            Op::Add { .. } => true,
            _ => false,
        }
    }

    /// `add_to_bytes` converts the Add `Op` to a vector of bytes.
    pub fn add_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Add { a, b } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();
                let b_buf = b.to_bytes();

                buf.push(Op::ADD_CODE);
                buf.extend_from_slice(&a_buf[..]);
                buf.extend_from_slice(&b_buf[..]);

                Ok(buf)
            }
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `add_from_bytes` creates an Add `Op` from a slice of bytes.
    pub fn add_from_bytes(buf: &[u8]) -> Result<Op> {
        if buf.len() != 65 {
            let err = Error::new_op("invalid op length", None);
            return Err(err);
        }

        if buf[0] != Op::ADD_CODE {
            let err = Error::new_op("invalid op code", None);
            return Err(err);
        }

        let mut a_buf = [0u8; 32];
        for (i, v) in buf[1..33].iter().enumerate() {
            a_buf[i] = *v;
        }

        let a = Label::from_bytes(a_buf);

        let mut b_buf = [0u8; 32];
        for (i, v) in buf[33..65].iter().enumerate() {
            b_buf[i] = *v;
        }

        let b = Label::from_bytes(b_buf);

        Op::new_add(&a, &b)
    }

    /// `new_mul` creates a new Mul `Op`.
    pub fn new_mul(a: &Label, b: &Label) -> Result<Op> {
        if a == b {
            let msg = "labels are not distinct";
            let source = None;
            let err = Error::new_op(msg, source);
            return Err(err);
        }

        let op = Op::Mul {
            a: Box::new(a.to_owned()),
            b: Box::new(b.to_owned()),
        };

        Ok(op)
    }

    /// `random_mul` creates a random Mul `Op`.
    pub fn random_mul() -> Result<Op> {
        let a = Label::random()?;
        let b = Label::random()?;

        Op::new_mul(&a, &b)
    }

    /// `random_mul_from_rng` creates a random Mul `Op` from a RNG.
    pub fn random_mul_from_rng<R>(rng: &mut R) -> Result<Op>
    where
        R: RngCore,
    {
        let a = Label::from_rng(rng)?;
        let b = Label::from_rng(rng)?;

        Op::new_mul(&a, &b)
    }

    /// `is_mul` returns if the `Op` is an Mul `Op`.
    pub fn is_mul(&self) -> bool {
        match self {
            Op::Mul { .. } => true,
            _ => false,
        }
    }

    /// `mul_to_bytes` converts the Mul `Op` to a vector of bytes.
    pub fn mul_to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Mul { a, b } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();
                let b_buf = b.to_bytes();

                buf.push(Op::MUL_CODE);
                buf.extend_from_slice(&a_buf[..]);
                buf.extend_from_slice(&b_buf[..]);

                Ok(buf)
            }
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `mul_from_bytes` creates an Mul `Op` from a slice of bytes.
    pub fn mul_from_bytes(buf: &[u8]) -> Result<Op> {
        if buf.len() != 65 {
            let err = Error::new_op("invalid op length", None);
            return Err(err);
        }

        if buf[0] != Op::MUL_CODE {
            let err = Error::new_op("invalid op code", None);
            return Err(err);
        }

        let mut a_buf = [0u8; 32];
        for (i, v) in buf[1..33].iter().enumerate() {
            a_buf[i] = *v;
        }

        let a = Label::from_bytes(a_buf);

        let mut b_buf = [0u8; 32];
        for (i, v) in buf[33..65].iter().enumerate() {
            b_buf[i] = *v;
        }

        let b = Label::from_bytes(b_buf);

        Op::new_mul(&a, &b)
    }

    /// `new_noop` creates a new Noop `Op`.
    pub fn new_noop() -> Op {
        Op::Noop
    }

    /// `is_noop` returns if the `Op` is an Noop `Op`.
    pub fn is_noop(&self) -> bool {
        match self {
            Op::Noop => true,
            _ => false,
        }
    }

    /// `noop_to_bytes` converts the Noop `Op` to a vector of bytes.
    pub fn noop_to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Op::Noop => Ok(vec![Op::NOOP_CODE]),
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `noop_from_bytes` creates an Noop `Op` from a slice of bytes.
    pub fn noop_from_bytes(buf: &[u8]) -> Result<Op> {
        if buf.len() != 1 {
            let err = Error::new_op("invalid op length", None);
            return Err(err);
        }

        if buf[0] != Op::NOOP_CODE {
            let err = Error::new_op("invalid op code", None);
            return Err(err);
        }

        let op = Op::new_noop();

        Ok(op)
    }

    /// `random` creates a random `Op`.
    pub fn random() -> Result<Op> {
        let idx = random_u32()?;

        let max = u32::max_value();

        if idx >= (max / 3) * 2 {
            Op::random_mul()
        } else if idx >= max / 3 {
            Op::random_add()
        } else {
            Ok(Op::new_noop())
        }
    }

    /// `from_rng` creates a random `Op` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<Op>
    where
        R: RngCore,
    {
        let idx = random_u32()?;

        let max = u32::max_value();

        if idx >= (max / 3) * 2 {
            Op::random_mul_from_rng(rng)
        } else if idx >= max / 3 {
            Op::random_add_from_rng(rng)
        } else {
            Ok(Op::new_noop())
        }
    }

    /// `labels` returns the `Op` labels.
    pub fn labels(&self) -> Vec<&Label> {
        let mut buf = Vec::new();

        match self {
            Op::Add { a, b } | Op::Mul { a, b } => {
                buf.push(&*(*a));
                buf.push(&*(*b));
            }
            Op::Noop => {}
        }

        buf
    }

    /// `to_bytes` converts the `Op` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Op::Noop => self.noop_to_bytes(),
            Op::Add { .. } => self.add_to_bytes(),
            Op::Mul { .. } => self.mul_to_bytes(),
        }
    }

    /// `from_bytes` creates an `Op` from a slice of bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Op> {
        if buf.len() > 65 {
            let err = Error::new_op("invalid op length", None);
            return Err(err);
        }

        match buf[0] {
            Op::NOOP_CODE => Op::noop_from_bytes(buf),
            Op::ADD_CODE => Op::add_from_bytes(buf),
            Op::MUL_CODE => Op::mul_from_bytes(buf),
            _ => {
                let err = Error::new_op("invalid op code", None);
                Err(err)
            }
        }
    }

    /// `validate` validates an `Op`.
    pub fn validate(&self) -> Result<()> {
        match self {
            Op::Add { a, b } | Op::Mul { a, b } => {
                if *a == *b {
                    let msg = "labels are not distinct";
                    let source = None;
                    let err = Error::new_op(msg, source);
                    Err(err)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }
}

impl Default for Op {
    fn default() -> Op {
        Op::Noop
    }
}

#[test]
fn test_op_noop_bytes() {
    let op_a = Op::new_noop();
    let res = op_a.to_bytes();
    assert!(res.is_ok());

    let buf = res.unwrap();
    let res = Op::noop_from_bytes(&buf);
    assert!(res.is_ok());

    let op_b = res.unwrap();
    assert_eq!(op_a, op_b);

    let invalid_length_buf = [0u8; 2];
    let res = Op::noop_from_bytes(&invalid_length_buf[..]);
    assert!(res.is_err());

    match res {
        Err(err) => {
            let msg: String = "invalid op length".into();
            assert_eq!(err.msg, msg)
        }
        _ => panic!("expected 'invalid op length'"),
    }

    let mut invalid_code_buf = [0u8; 1];
    invalid_code_buf[0] = Op::NOOP_CODE + 1;
    let res = Op::noop_from_bytes(&invalid_code_buf[..]);
    assert!(res.is_err());

    match res {
        Err(err) => {
            let msg: String = "invalid op code".into();
            assert_eq!(err.msg, msg)
        }
        _ => panic!("expected 'invalid op code'"),
    }
}

#[test]
fn test_op_new_add() {
    for _ in 0..10 {
        let a = Label::random().unwrap();

        let mut b = Label::random().unwrap();
        while b == a {
            b = Label::random().unwrap();
        }

        let res = Op::new_add(&a, &b);
        assert!(res.is_ok());

        let valid_op = res.unwrap();
        let res = valid_op.validate();
        assert!(res.is_ok());

        let invalid_op = Op::Add {
            a: Box::new(a.clone()),
            b: Box::new(a.clone()),
        };

        let res = invalid_op.validate();
        assert!(res.is_err());
    }
}

#[test]
fn test_op_random_add() {
    for _ in 0..10 {
        let op = Op::random_add().unwrap();
        let res = op.validate();
        assert!(res.is_ok());

        let is_add = op.is_add();
        assert!(is_add)
    }
}

#[test]
fn test_op_add_bytes() {
    for _ in 0..10 {
        let op_a = Op::random_add().unwrap();
        let res = op_a.to_bytes();
        assert!(res.is_ok());

        let buf = res.unwrap();
        let res = Op::add_from_bytes(&buf);
        assert!(res.is_ok());

        let op_b = res.unwrap();
        assert_eq!(op_a, op_b);

        let invalid_length_buf = [0u8; 66];
        let res = Op::add_from_bytes(&invalid_length_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op length".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op length'"),
        }

        let mut invalid_code_buf = [0u8; 65];
        invalid_code_buf[0] = Op::ADD_CODE + 1;
        let res = Op::add_from_bytes(&invalid_code_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op code".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op code'"),
        }
    }
}

#[test]
fn test_op_new_mul() {
    for _ in 0..10 {
        let a = Label::random().unwrap();

        let mut b = Label::random().unwrap();
        while b == a {
            b = Label::random().unwrap();
        }

        let res = Op::new_mul(&a, &b);
        assert!(res.is_ok());

        let valid_op = res.unwrap();
        let res = valid_op.validate();
        assert!(res.is_ok());

        let invalid_op = Op::Mul {
            a: Box::new(a.clone()),
            b: Box::new(a.clone()),
        };

        let res = invalid_op.validate();
        assert!(res.is_err());
    }
}

#[test]
fn test_op_random_mul() {
    for _ in 0..10 {
        let op = Op::random_mul().unwrap();
        let res = op.validate();
        assert!(res.is_ok());

        let is_mul = op.is_mul();
        assert!(is_mul)
    }
}

#[test]
fn test_op_mul_bytes() {
    for _ in 0..10 {
        let op_a = Op::random_mul().unwrap();
        let res = op_a.to_bytes();
        assert!(res.is_ok());

        let buf = res.unwrap();
        let res = Op::mul_from_bytes(&buf);
        assert!(res.is_ok());

        let op_b = res.unwrap();
        assert_eq!(op_a, op_b);

        let invalid_length_buf = [0u8; 66];
        let res = Op::mul_from_bytes(&invalid_length_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op length".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op length'"),
        }

        let mut invalid_code_buf = [0u8; 65];
        invalid_code_buf[0] = Op::MUL_CODE + 1;
        let res = Op::mul_from_bytes(&invalid_code_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op code".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op code'"),
        }
    }
}

#[test]
fn test_op_bytes() {
    let noop_a = Op::new_noop();

    let res = noop_a.to_bytes();
    assert!(res.is_ok());

    let noop_buf = res.unwrap();
    let res = Op::from_bytes(&noop_buf);
    assert!(res.is_ok());

    let noop_b = res.unwrap();
    assert_eq!(noop_a, noop_b);

    for _ in 0..10 {
        let add_a = Op::random_add().unwrap();
        let mul_a = Op::random_mul().unwrap();

        let invalid_length_buf = [0u8; 66];
        let res = Op::from_bytes(&invalid_length_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op length".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op length'"),
        }

        let mut invalid_code_buf = [0u8; 65];
        invalid_code_buf[0] = 255;
        let res = Op::from_bytes(&invalid_code_buf[..]);
        assert!(res.is_err());

        match res {
            Err(err) => {
                let msg: String = "invalid op code".into();
                assert_eq!(err.msg, msg)
            }
            _ => panic!("expected 'invalid op code'"),
        }

        let res = add_a.to_bytes();
        assert!(res.is_ok());

        let add_buf = res.unwrap();
        let res = Op::from_bytes(&add_buf);
        assert!(res.is_ok());

        let add_b = res.unwrap();
        assert_eq!(add_a, add_b);

        let res = mul_a.to_bytes();
        assert!(res.is_ok());

        let mul_buf = res.unwrap();
        let res = Op::from_bytes(&mul_buf);
        assert!(res.is_ok());

        let mul_b = res.unwrap();
        assert_eq!(mul_a, mul_b);
    }
}

#[test]
fn test_op_validate() {
    let valid_noop = Op::new_noop();

    let res = valid_noop.validate();
    assert!(res.is_ok());

    for _ in 0..10 {
        let valid_add = Op::random_add().unwrap();
        let valid_mul = Op::random_mul().unwrap();

        let res = valid_add.validate();
        assert!(res.is_ok());

        let res = valid_mul.validate();
        assert!(res.is_ok());

        let label = Label::random().unwrap();
        let mut other_label = Label::random().unwrap();
        while other_label == label {
            other_label = Label::random().unwrap();
        }

        let invalid_add = Op::Add {
            a: Box::new(label),
            b: Box::new(label),
        };

        let res = invalid_add.validate();
        assert!(res.is_err());

        let invalid_mul = Op::Mul {
            a: Box::new(label),
            b: Box::new(label),
        };

        let res = invalid_mul.validate();
        assert!(res.is_err());
    }
}

/// `Node` is a node in the arithmetic circuit in the field of order
/// q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug, Serialize, Deserialize)]
pub struct Node {
    label: Label,
    pub nonce: u32,
    pub op: Op,
    pub value: Option<Value>,
}

impl Node {
    /// `new` creates a new `Node`.
    pub fn new(nonce: u32, op: &Op, value: Option<Value>) -> Result<Node> {
        op.validate()?;

        let label = Label::from_node_data(nonce, op, value)?;

        let node = Node {
            label,
            nonce,
            op: op.to_owned(),
            value,
        };

        Ok(node)
    }

    /// `random_with_op` creates a new random `Node` with a specific `Op`.
    pub fn random_with_op(op: &Op) -> Result<Node> {
        let nonce = random_u32()?;
        let value = if random_bool()? {
            let value = Value::random()?;
            Some(value)
        } else {
            None
        };

        Node::new(nonce, op, value)
    }

    /// `random_noop` creates a new random `Node` with Noop `Op`.
    pub fn random_noop() -> Result<Node> {
        let op = Op::new_noop();
        Node::random_with_op(&op)
    }

    /// `random_add` creates a new random `Node` with Add `Op`.
    pub fn random_add() -> Result<Node> {
        let op = Op::random_add()?;
        Node::random_with_op(&op)
    }

    /// `random_mul` creates a new random `Node` with Mul `Op`.
    pub fn random_mul() -> Result<Node> {
        let op = Op::random_mul()?;
        Node::random_with_op(&op)
    }

    /// `random` creates a new random `Node`.
    pub fn random() -> Result<Node> {
        let mut rng = OsRng::new().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        Node::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `Node` from a given RNG.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<Node>
    where
        R: RngCore + CryptoRng,
    {
        let nonce = random_u32()?;
        let op = Op::from_rng(&mut rng)?;
        let value = if random_bool()? {
            let value = Value::from_rng(&mut rng);
            Some(value)
        } else {
            None
        };

        Node::new(nonce, &op, value)
    }

    /// `to_bytes` converts the `Node` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.label.to_bytes()[..]);
        buf.write_u32::<LittleEndian>(self.nonce).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let op_buf = self.op.to_bytes()?;
        let op_buf_len = op_buf.len() as u32;

        buf.write_u32::<LittleEndian>(op_buf_len).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        buf.extend_from_slice(&op_buf);

        if let Some(value) = self.value {
            buf.write_u32::<LittleEndian>(1u32).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            buf.extend_from_slice(&value.to_bytes()[..]);
        } else {
            buf.write_u32::<LittleEndian>(0u32).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;
        }

        Ok(buf)
    }

    /// `from_bytes` creates a new `Node` from a slice of bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Node> {
        if buf.len() < 45 {
            let err = Error::new_io("invalid length", None);
            return Err(err);
        }

        let mut reader = Cursor::new(buf);

        let mut label_buf = [0u8; 32];

        reader.read_exact(&mut label_buf[..]).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let label = Label::from_bytes(label_buf);

        let nonce = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let op_buf_len = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut op_buf = Vec::new();
        op_buf.resize(op_buf_len as usize, 0);

        reader.read_exact(&mut op_buf).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let op = Op::from_bytes(&op_buf)?;

        let value_flag = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut value = None;

        if value_flag == 1 {
            let mut value_buf = [0u8; 32];

            reader.read_exact(&mut value_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            value = Some(Value::from_bytes(value_buf)?);
        } else if value_flag != 0 {
            let err = Error::new_node("invalid value", None);
            return Err(err);
        }

        let node = Node {
            label,
            nonce,
            op,
            value,
        };

        node.validate()?;

        Ok(node)
    }

    /// `validate` validates the `Node`.
    pub fn validate(&self) -> Result<()> {
        self.op.validate()?;

        let label = Label::from_node_data(self.nonce, &self.op, self.value)?;
        if label != self.label {
            let msg = "invalid label";
            let source = None;
            let err = Error::new_node(msg, source);
            Err(err)
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_node_new() {
    for _ in 0..10 {
        let nonce = random_u32().unwrap();
        let valid_op = Op::random().unwrap();
        let source = if random_bool().unwrap() {
            let value = Value::random().unwrap();
            Some(value)
        } else {
            None
        };

        let res = Node::new(nonce, &valid_op, source.clone());
        assert!(res.is_ok());

        let node = res.unwrap();
        let res = node.validate();
        assert!(res.is_ok());

        let label = Label::random().unwrap();

        let invalid_op = Op::Mul {
            a: Box::new(label),
            b: Box::new(label),
        };

        let res = Node::new(nonce, &invalid_op, source);
        assert!(res.is_err());
    }
}

#[test]
fn test_node_random() {
    for _ in 0..10 {
        let res = Node::random();
        assert!(res.is_ok());

        let node = res.unwrap();
        let res = node.validate();
        assert!(res.is_ok())
    }
}

#[test]
fn test_node_bytes() {
    for _ in 0..10 {
        let node_a = Node::random().unwrap();

        let res = node_a.to_bytes();
        assert!(res.is_ok());
        let node_buf = res.unwrap();

        let res = Node::from_bytes(&node_buf);
        assert!(res.is_ok());
        let node_b = res.unwrap();

        assert_eq!(node_a, node_b);
    }
}

#[test]
fn test_node_validate() {
    for _ in 0..10 {
        let res = Node::random();
        assert!(res.is_ok());

        let node = res.unwrap();
        let res = node.validate();
        assert!(res.is_ok());

        let label = Label::random().unwrap();

        let invalid_op = Op::Mul {
            a: Box::new(label),
            b: Box::new(label),
        };

        let mut invalid_op_node = node.clone();
        invalid_op_node.op = invalid_op;
        let res = invalid_op_node.validate();
        assert!(res.is_err());

        let mut invalid_label_node = node.clone();
        let mut invalid_label = Label::random().unwrap();
        while invalid_label == node.label {
            invalid_label = Label::random().unwrap();
        }
        invalid_label_node.label = invalid_label;
        let res = invalid_label_node.validate();
        assert!(res.is_err());
    }
}

/// `Circuit` is an arithmetic circuit in the field of order q = 2^255 -19.
#[derive(Clone, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct Circuit {
    pub id: [u8; 32],
    public_inputs_len: u32,
    pub public_inputs: Vec<Label>,
    nondet_inputs_len: u32,
    pub nondet_inputs: Vec<Label>,
    public_outputs_len: u32,
    pub public_outputs: Vec<Label>,
    nodes_len: u32,
    pub nodes: BTreeMap<Label, Node>,
}

impl Circuit {
    /// `new` creates a new `Circuit`.
    pub fn new() -> Result<Circuit> {
        let mut circuit = Circuit::default();
        circuit.update_id()?;

        Ok(circuit)
    }

    /// `update_id` updates the `Circuit` id.
    pub fn update_id(&mut self) -> Result<()> {
        self.id = self.calc_id()?;

        Ok(())
    }

    /// `calc_id` calculates the `Circuit` id.
    pub fn calc_id(&self) -> Result<[u8; 32]> {
        let mut clone = self.clone();
        clone.id = [0u8; 32];

        let buf = clone.to_bytes()?;

        let mut id = [0u8; 32];

        for (i, v) in Sha256::digest(&buf).iter().enumerate() {
            id[i] = *v;
        }

        Ok(id)
    }

    /// `public_inputs_len` returns the length of the `Circuit` public inputs.
    pub fn public_inputs_len(&self) -> u32 {
        self.public_inputs_len
    }

    /// `nondet_inputs_len` returns the length of the `Circuit` nondet inputs.
    pub fn nondet_inputs_len(&self) -> u32 {
        self.nondet_inputs_len
    }

    /// `public_outputs_len` returns the length of the `Circuit` public outputs.
    pub fn public_outputs_len(&self) -> u32 {
        self.public_outputs_len
    }

    /// `nodes_len` returns the length of the `Circuit` nodes.
    pub fn nodes_len(&self) -> u32 {
        self.nodes_len
    }

    /// `internal_nodes_len` returns the length of the `Circuit` internal nodes.
    pub fn internal_nodes_len(&self) -> u32 {
        self.nodes_len - self.public_inputs_len - self.nondet_inputs_len - self.public_outputs_len
    }

    /// `insert_node` inserts a `Node` in the `Circuit`. The `Node` `Op`
    /// labels are expected to be keys in the current `Circuit`.
    fn insert_node(&mut self, node: Node) -> Result<()> {
        self.validate()?;
        node.validate()?;

        if self.lookup_node(&node.label) {
            let err = Error::new_circuit("node already found", None);
            return Err(err);
        }

        for label in node.op.labels() {
            if !self.lookup_node(label) {
                let err = Error::new_circuit("node not found", None);
                return Err(err);
            }
        }

        self.nodes.insert(node.label, node);

        self.nodes_len += 1;

        self.update_id()?;
        self.validate()?;

        Ok(())
    }

    /// `lookup_node` finds a `Node` in the `Circuit`.
    pub fn lookup_node(&self, label: &Label) -> bool {
        self.nodes.contains_key(label)
    }

    /// `get_node` gets a `Node` from the `Circuit`.
    pub fn get_node(&self, label: &Label) -> Option<&Node> {
        self.nodes.get(label)
    }

    /// `insert_public_input` inserts a `Node` in the `Circuit` public inputs.
    pub fn insert_public_input(&mut self, node: Node) -> Result<()> {
        self.validate()?;
        node.validate()?;

        if !node.op.is_noop() {
            let err = Error::new_circuit("invalid op", None);
            return Err(err);
        }

        let label = node.label;

        if self.lookup_public_input(&label) {
            let err = Error::new_circuit("already found", None);
            return Err(err);
        }

        self.insert_node(node)?;

        self.public_inputs.push(label);

        self.public_inputs_len += 1;

        self.update_id()?;
        self.validate()?;

        Ok(())
    }

    /// `lookup_public_input` finds a public input `Node` in the `Circuit`.
    pub fn lookup_public_input(&self, label: &Label) -> bool {
        self.public_inputs.contains(label)
    }

    /// `get_public_input` gets a public input `Node` from the `Circuit`.
    pub fn get_public_input(&self, label: &Label) -> Option<&Node> {
        if !self.lookup_public_input(label) {
            None
        } else {
            self.get_node(label)
        }
    }

    /// `create_nondet_input` creates a nondeterministic input `Node` in the `Circuit`.
    pub fn create_nondet_input(&mut self) -> Result<Node> {
        self.validate()?;

        let node = Node::random_noop()?;

        self.insert_nondet_input(node.clone())?;

        Ok(node)
    }

    /// `insert_nondet_input` inserts a `Node` in the `Circuit` nondet inputs.
    pub fn insert_nondet_input(&mut self, node: Node) -> Result<()> {
        self.validate()?;
        node.validate()?;

        if !node.op.is_noop() {
            let err = Error::new_circuit("invalid op", None);
            return Err(err);
        }

        let label = node.label;

        if self.lookup_nondet_input(&label) {
            let err = Error::new_circuit("already found", None);
            return Err(err);
        }

        self.insert_node(node)?;

        self.nondet_inputs.push(label);

        self.nondet_inputs_len += 1;

        self.update_id()?;
        self.validate()?;

        Ok(())
    }

    /// `lookup_nondet_input` finds a nondet input `Node` in the `Circuit`.
    pub fn lookup_nondet_input(&self, label: &Label) -> bool {
        self.nondet_inputs.contains(label)
    }

    /// `get_nondet_input` gets a nondet input `Node` from the `Circuit`.
    pub fn get_nondet_input(&self, label: &Label) -> Option<&Node> {
        if !self.lookup_nondet_input(label) {
            None
        } else {
            self.get_node(label)
        }
    }

    /// `insert_public_output` inserts a `Node` in the `Circuit` public outputs.
    pub fn insert_public_output(&mut self, node: Node) -> Result<()> {
        self.validate()?;
        node.validate()?;

        if node.op.is_noop() {
            let err = Error::new_circuit("invalid op", None);
            return Err(err);
        }

        let label = node.label;

        if self.lookup_public_output(&label) {
            let err = Error::new_circuit("already found", None);
            return Err(err);
        }

        self.insert_node(node)?;

        self.public_outputs.push(label);

        self.public_outputs_len += 1;

        self.update_id()?;
        self.validate()?;

        Ok(())
    }

    /// `lookup_public_output` finds a public output `Node` in the `Circuit`.
    pub fn lookup_public_output(&self, label: &Label) -> bool {
        self.public_outputs.contains(label)
    }

    /// `get_public_output` gets a public output `Node` from the `Circuit`.
    pub fn get_public_output(&self, label: &Label) -> Option<&Node> {
        if !self.lookup_public_output(label) {
            None
        } else {
            self.get_node(label)
        }
    }

    /// `insert_internal_node` inserts an internal `Node` in the `Circuit`.
    pub fn insert_internal_node(&mut self, node: Node) -> Result<()> {
        self.validate()?;
        node.validate()?;

        if self.lookup_public_input(&node.label)
            || self.lookup_nondet_input(&node.label)
            || self.lookup_public_output(&node.label)
        {
            let err = Error::new_circuit("invalid node", None);
            return Err(err);
        }

        if node.op.is_noop() {
            let err = Error::new_circuit("invalid op", None);
            return Err(err);
        }

        self.insert_node(node)
    }

    /// `g_polynomial` calculates the G polynomial of the `Circuit` given a value tau.
    pub fn g_polynomial(_tau: Value) -> Result<Vec<Value>> {
        unreachable!() // TODO
    }

    /// `to_bytes` converts the `Circuit` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&self.id[..]);

        buf.write_u32::<LittleEndian>(self.public_inputs_len)
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        for label in self.public_inputs.clone() {
            buf.extend_from_slice(&label.to_bytes()[..]);
        }

        buf.write_u32::<LittleEndian>(self.nondet_inputs_len)
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        for label in self.nondet_inputs.clone() {
            buf.extend_from_slice(&label.to_bytes()[..]);
        }

        buf.write_u32::<LittleEndian>(self.public_outputs_len)
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        for label in self.public_outputs.clone() {
            buf.extend_from_slice(&label.to_bytes()[..]);
        }

        buf.write_u32::<LittleEndian>(self.nodes_len).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        for (label, node) in self.nodes.clone() {
            buf.extend_from_slice(&label.to_bytes()[..]);

            let node_buf = node.to_bytes()?;

            let node_buf_len = node_buf.len() as u32;

            buf.write_u32::<LittleEndian>(node_buf_len).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            buf.extend_from_slice(&node_buf);
        }

        Ok(buf)
    }

    /// `from_bytes` creates a new `Circuit` from a slice of bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Circuit> {
        if buf.len() < 48 {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        let mut reader = Cursor::new(buf);

        let mut id = [0u8; 32];
        reader.read_exact(&mut id[..]).map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let public_inputs_len = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut public_inputs: Vec<Label> = Vec::new();

        for _ in 0..public_inputs_len {
            let mut label_buf = [0u8; 32];

            reader.read_exact(&mut label_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let label = Label::from_bytes(label_buf);

            public_inputs.push(label);
        }

        let nondet_inputs_len = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut nondet_inputs: Vec<Label> = Vec::new();

        for _ in 0..nondet_inputs_len {
            let mut label_buf = [0u8; 32];

            reader.read_exact(&mut label_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let label = Label::from_bytes(label_buf);

            nondet_inputs.push(label);
        }

        let public_outputs_len = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut public_outputs: Vec<Label> = Vec::new();

        for _ in 0..public_outputs_len {
            let mut label_buf = [0u8; 32];

            reader.read_exact(&mut label_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let label = Label::from_bytes(label_buf);

            public_outputs.push(label);
        }

        let nodes_len = reader.read_u32::<LittleEndian>().map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

        let mut nodes: BTreeMap<Label, Node> = BTreeMap::new();

        for _ in 0..nodes_len {
            let mut label_buf = [0u8; 32];

            reader.read_exact(&mut label_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let label = Label::from_bytes(label_buf);

            let node_buf_len = reader.read_u32::<LittleEndian>().map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let mut node_buf = Vec::new();
            node_buf.resize(node_buf_len as usize, 0);

            reader.read_exact(&mut node_buf[..]).map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

            let node = Node::from_bytes(&node_buf)?;

            nodes.insert(label, node);
        }

        let circuit = Circuit {
            id,
            public_inputs_len,
            public_inputs,
            nondet_inputs_len,
            nondet_inputs,
            public_outputs_len,
            public_outputs,
            nodes_len,
            nodes,
        };

        circuit.validate()?;

        Ok(circuit)
    }

    /// `validate` validates the `Circuit`.
    pub fn validate(&self) -> Result<()> {
        if self.public_inputs.len() != self.public_inputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        for label in self.public_inputs.clone() {
            if !self.nodes.contains_key(&label) {
                let err = Error::new_circuit("node not found", None);
                return Err(err);
            }

            if !self.nodes.get(&label).unwrap().op.is_noop() {
                let err = Error::new_circuit("invalid op", None);
                return Err(err);
            }
        }

        if self.nondet_inputs.len() != self.nondet_inputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        for label in self.nondet_inputs.clone() {
            if !self.nodes.contains_key(&label) {
                let err = Error::new_circuit("node not found", None);
                return Err(err);
            }

            if !self.nodes.get(&label).unwrap().op.is_noop() {
                let err = Error::new_circuit("invalid op", None);
                return Err(err);
            }
        }

        if self.public_outputs.len() != self.public_outputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        for label in self.public_outputs.clone() {
            if !self.nodes.contains_key(&label) {
                let err = Error::new_circuit("node not found", None);
                return Err(err);
            }

            if self.nodes.get(&label).unwrap().op.is_noop() {
                let err = Error::new_circuit("invalid op", None);
                return Err(err);
            }
        }

        if self.nodes.len() != self.nodes_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        for (label, node) in self.nodes.iter() {
            node.validate()?;

            if label != &node.label {
                let err = Error::new_circuit("invalid nodes", None);
                return Err(err);
            }
        }

        if self.id != self.calc_id()? {
            let err = Error::new_circuit("invalid id", None);
            return Err(err);
        }

        Ok(())
    }
}

#[test]
fn test_circuit_new() {
    let res = Circuit::new();
    assert!(res.is_ok());
}

#[test]
fn test_circuit_public_inputs() {
    let mut circuit = Circuit::new().unwrap();
    let node_a = Node::random_noop().unwrap();
    let node_b = Node::random_add().unwrap();

    let mut public_inputs_len = circuit.public_inputs_len();
    assert_eq!(public_inputs_len, 0);

    let mut nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 0);

    let res = circuit.insert_public_input(node_a.clone());
    assert!(res.is_ok());

    public_inputs_len = circuit.public_inputs_len();
    assert_eq!(public_inputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 1);

    let res = circuit.insert_public_input(node_a.clone());
    assert!(res.is_err());

    public_inputs_len = circuit.public_inputs_len();
    assert_eq!(public_inputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 1);

    let res = circuit.insert_public_input(node_b.clone());
    assert!(res.is_err());

    let found = circuit.lookup_public_input(&node_a.label);
    assert!(found);

    assert!(circuit.get_public_input(&node_a.label).is_some());
    assert_eq!(circuit.get_public_input(&node_a.label).unwrap(), &node_a,);
}

#[test]
fn test_circuit_nondet_inputs() {
    let mut circuit = Circuit::new().unwrap();
    let node_a = Node::random_noop().unwrap();
    let node_b = Node::random_add().unwrap();

    let mut nondet_inputs_len = circuit.nondet_inputs_len();
    assert_eq!(nondet_inputs_len, 0);

    let mut nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 0);

    let res = circuit.insert_nondet_input(node_a.clone());
    assert!(res.is_ok());

    nondet_inputs_len = circuit.nondet_inputs_len();
    assert_eq!(nondet_inputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 1);

    let res = circuit.insert_nondet_input(node_a.clone());
    assert!(res.is_err());

    nondet_inputs_len = circuit.nondet_inputs_len();
    assert_eq!(nondet_inputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 1);

    let res = circuit.insert_nondet_input(node_b.clone());
    assert!(res.is_err());

    let found = circuit.lookup_nondet_input(&node_a.label);
    assert!(found);

    assert!(circuit.get_nondet_input(&node_a.label).is_some());
    assert_eq!(circuit.get_nondet_input(&node_a.label).unwrap(), &node_a,);

    let res = circuit.create_nondet_input();

    assert!(res.is_ok());

    nondet_inputs_len = circuit.nondet_inputs_len();
    assert_eq!(nondet_inputs_len, 2);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 2);
}

#[test]
fn test_circuit_internal_nodes() {
    let mut circuit = Circuit::new().unwrap();

    let node_a = Node::random_noop().unwrap();
    circuit.insert_public_input(node_a.clone()).unwrap();

    let node_b = Node::random_noop().unwrap();
    circuit.insert_nondet_input(node_b.clone()).unwrap();

    let op = Op::new_add(&node_a.label, &node_b.label).unwrap();
    let node_c = Node::random_with_op(&op).unwrap();

    let node_d = Node::random_add().unwrap();
    let node_e = Node::random_mul().unwrap();
    let node_f = Node::random_noop().unwrap();

    let mut internal_nodes_len = circuit.internal_nodes_len();
    assert_eq!(internal_nodes_len, 0);

    let mut nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 2);

    let res = circuit.insert_internal_node(node_c.clone());
    assert!(res.is_ok());

    internal_nodes_len = circuit.internal_nodes_len();
    assert_eq!(internal_nodes_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_internal_node(node_d.clone());
    assert!(res.is_err());

    internal_nodes_len = circuit.internal_nodes_len();
    assert_eq!(internal_nodes_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_internal_node(node_e.clone());
    assert!(res.is_err());

    internal_nodes_len = circuit.internal_nodes_len();
    assert_eq!(internal_nodes_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_internal_node(node_f.clone());
    assert!(res.is_err());

    internal_nodes_len = circuit.internal_nodes_len();
    assert_eq!(internal_nodes_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_internal_node(node_c.clone());
    assert!(res.is_err());

    let found = circuit.lookup_node(&node_c.label);
    assert!(found);

    assert!(circuit.get_node(&node_c.label).is_some());
    assert_eq!(circuit.get_node(&node_c.label).unwrap(), &node_c,);
}

#[test]
fn test_circuit_public_outputs() {
    let mut circuit = Circuit::new().unwrap();

    let node_a = Node::random_noop().unwrap();
    circuit.insert_public_input(node_a.clone()).unwrap();

    let node_b = Node::random_noop().unwrap();
    circuit.insert_nondet_input(node_b.clone()).unwrap();

    let op = Op::new_add(&node_a.label, &node_b.label).unwrap();
    let node_c = Node::random_with_op(&op).unwrap();

    let node_d = Node::random_noop().unwrap();

    let mut public_outputs_len = circuit.public_outputs_len();
    assert_eq!(public_outputs_len, 0);

    let mut nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 2);

    let res = circuit.insert_public_output(node_c.clone());
    assert!(res.is_ok());

    public_outputs_len = circuit.public_outputs_len();
    assert_eq!(public_outputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_public_output(node_c.clone());
    assert!(res.is_err());

    public_outputs_len = circuit.public_outputs_len();
    assert_eq!(public_outputs_len, 1);

    nodes_len = circuit.nodes_len();
    assert_eq!(nodes_len, 3);

    let res = circuit.insert_public_output(node_d.clone());
    assert!(res.is_err());

    let found = circuit.lookup_public_output(&node_c.label);
    assert!(found);

    assert!(circuit.get_public_output(&node_c.label).is_some());
    assert_eq!(circuit.get_public_output(&node_c.label).unwrap(), &node_c,);
}

#[test]
fn test_circuit_new_bytes() {
    // NB: this has to be substituted

    let circuit_a = Circuit::new().unwrap();
    let res = circuit_a.to_bytes();
    assert!(res.is_ok());

    let circuit_buf = res.unwrap();
    let res = Circuit::from_bytes(&circuit_buf);
    assert!(res.is_ok());

    let circuit_b = res.unwrap();
    assert_eq!(circuit_a, circuit_b)
}

#[test]
fn test_circuit_bytes() {
    let mut circuit_a = Circuit::new().unwrap();

    let node_a = Node::random_noop().unwrap();
    circuit_a.insert_public_input(node_a.clone()).unwrap();

    let node_b = Node::random_noop().unwrap();
    circuit_a.insert_public_input(node_b.clone()).unwrap();

    let op = Op::new_add(&node_a.label, &node_b.label).unwrap();
    let node_c = Node::random_with_op(&op).unwrap();
    circuit_a.insert_public_output(node_c).unwrap();

    let res = circuit_a.validate();
    if res.is_err() {
        panic!(format!("{:?}", res));
    }
    assert!(res.is_ok());

    let res = circuit_a.to_bytes();
    assert!(res.is_ok());

    let circuit_buf = res.unwrap();
    let res = Circuit::from_bytes(&circuit_buf);
    if res.is_err() {
        panic!(format!("{:?}", res));
    }
    assert!(res.is_ok());

    let circuit_b = res.unwrap();

    let res = circuit_b.validate();
    assert!(res.is_ok());

    assert_eq!(circuit_a, circuit_b)
}

#[test]
fn test_circuit_validate() {
    let new = Circuit::new().unwrap();
    let res = new.validate();
    assert!(res.is_ok());
}

/// `Commitment` is a commitment to a multilinear polynomial.
pub struct Commitment;

/// `ProverInterface` is a trait implemented by Spartan provers.
pub trait ProverInterface {
    /// `get_commit` receives a `Commitment` to the multilinear polynomial Z'.
    fn get_commit(&self) -> Result<Commitment>;

    /// `set_tau` sets the random `Value` tau.
    fn set_tau(&mut self, _tau: Value) -> Result<()>;

    /// `eval_values` evaluates three values in Z'.
    fn eval_values(&mut self, _z1: Value, _z2: Value, _z3: Value) -> Result<(Value, Value, Value)>;

    /// `poly_eval` decommits the evaluation of Z' of a specific value.
    fn poly_eval(&mut self, _z: Value) -> Result<(Value, Value)>;

    /// `poly_evals` decommits the evalution of Z' of three given values.
    fn poly_evals(&mut self, _z1: Value, _z2: Value, _z3: Value) -> Result<(Value, Value)>;
}

/// `LocalProver` is a local Spartan protocol prover.
pub struct LocalProver;

/// `RemoveProver` is a remote Spartan protocol prover.
pub struct RemoteProver;

/// GPolynomial is the type of the G multilinear polynomial on the Circuit C.
pub struct GPolynomial {
    pub circuit: Circuit,
    pub tau: Value,
}

impl GPolynomial {
    // `new` creates a new `GPolynomial`.
    pub fn new(_circuit: &Circuit, _tau: Value) -> Result<GPolynomial> {
        unreachable!() // TODO
    }
}

/// `Verifier` is a Spartan protocol verifier.
pub struct Verifier {
    pub circuit: Circuit,
    pub xs: Vec<Value>,
    pub yx: Vec<Value>,
    pub poly_param: Value,
    pub comp_param: Value,
    pub comp_commit: Commitment,
}

impl Verifier {
    /// `new` creates a new `Verifier`.
    pub fn new(_circuit: &Circuit,
               _xs: Vec<Value>,
               _yx: Vec<Value>,
               _poly_param: Value,
               _comp_param: Value,
               _comp_commit: Commitment,
    ) -> Result<Verifier> {
        unreachable!() // TODO
    }

    /// `sumcheck` calculates the sumcheck of a `GPolynomial`.
    pub fn sumcheck(&self, _g: GPolynomial, _m: u32, _h: u32, _l: u32) -> Result<(Value, Value, Value, Value)> {
        unreachable!() // TODO
    }

    /// `reduce` reduces the sumcheck and evaluated values.
    #[allow(clippy::too_many_arguments)]
    pub fn reduce(&self, _s: u32, _z1: Value, _v1: Value, _z2: Value, _v2: Value, _z3: Value, _v3: Value) -> Result<(Value, Value)> {
        unreachable!() // TODO
    }

    /// `poly_eval_verify` verifies the `poly_eval` operation of an implementor
    /// of `ProverInterface`.
    pub fn poly_eval_verify(&self, _zc: Commitment, _z4: Value, _v4: Value, _pi4: Value) -> Result<bool> {
        unreachable!() // TODO
    }

    /// `exec` execs the `Verifier` against a `ProverInterface` implementor.
    #[allow(clippy::many_single_char_names)]
    pub fn exec<P: ProverInterface>(&self, prover: &mut P) -> Result<bool> {
        let zc = prover.get_commit()?;

        let tau = Value::random()?;
        prover.set_tau(tau)?;

        let m = 3*Label::LENGTH;
        let h = 0;
        let l = 3;

        let g = GPolynomial::new(&self.circuit, tau)?;
        let (_e, z1, z2, z3) = self.sumcheck(g, m, h, l)?;

        let (v1, v2, v3) = prover.eval_values(z1, z2, z3)?;
        let (z4, v4) = self.reduce(Label::LENGTH, z1, v1, z2, v2, z3, v3)?;

        let (_v4i, pi4) = prover.poly_eval(z4)?;
        let b = self.poly_eval_verify(zc, z4, v4, pi4)?;
        if !b {
            return Ok(false);
        }

        // TODO

        Ok(false)
    }
}
