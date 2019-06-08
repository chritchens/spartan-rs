use typenum::consts::U256;
use generic_array::{ArrayLength, GenericArray};
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng};
use rand_os::OsRng;
use digest::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::fmt;
use std::error;
use std::result;
use std::ops::{Index, IndexMut};

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
    source: Option<Box<dyn error::Error + 'static>>
}

impl Error {
    /// `new` creates a new `Error`.
    pub fn new(kind: ErrorKind, msg: &str, source: Option<Box<dyn error::Error + 'static>>) -> Error {
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
            ErrorKind::Other => write!(f, "Other: {}", self.msg)
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
    let mut rng = OsRng::new()
        .map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

    let res = random_bytes_from_rng(&mut rng, len);
    Ok(res)
}

/// `random_bytes_from_rng` creates a vector of random bytes using a given RNG.
pub fn random_bytes_from_rng<R>(rng: &mut R, len: usize) -> Vec<u8>
    where R: RngCore
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
    let mut rng = OsRng::new()
        .map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

    let res = random_u32_from_rng(&mut rng);
    Ok(res)
}

/// `random_u32_from_rng` returns a random `u32` using a given RNG.
pub fn random_u32_from_rng<R>(rng: &mut R) -> u32
    where R: RngCore
{
    rng.next_u32()
}

/// `random_bool` returns a random `bool`.
#[allow(dead_code)]
fn random_bool() -> Result<bool> {
    let mut rng = OsRng::new()
        .map_err(|e| {
            let msg = format!("{}", e);
            let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
            Error::new_io(&msg, source)
        })?;

    let res = random_bool_from_rng(&mut rng);
    Ok(res)
}

/// `random_bool_from_rng` returns a random `bool` using a given RNG.
pub fn random_bool_from_rng<R>(rng: &mut R) -> bool
    where R: RngCore
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
    where N: ArrayLength<bool>;

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
        let mut rng = OsRng::new()
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        BitArray256::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `BitArray256` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<BitArray256>
        where R: RngCore
    {
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf)
            .map_err(|e| {
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
               ba[i*8 + j] = extract_bit(buf[i], j);
            }
        }

        ba
    }

    /// `to_bytes` converts the `BitArray256` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];

        for i in 0..32 {
            for j in 0..8 {
                buf[i] = change_bit(buf[i], j, self[i*8 +j]);
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
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct Value(Scalar);

impl Value {
    /// `new` creates a new `Value` from a `Scalar`.
    pub fn new(s: Scalar) -> Value {
        Value(s)
    }

    /// `random` creates a new random `Value`.
    pub fn random() -> Result<Value> {
        let mut rng = OsRng::new()
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        let value = Value::from_rng(&mut rng);
        Ok(value)
    }

    /// `from_rng` creates a new random `Value` from a given RNG.
    pub fn from_rng<R>(mut rng: &mut R) -> Value
        where R: RngCore + CryptoRng
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
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Label(BitArray256);

impl Label {
    /// `new` creates a new `Label` for a slice of bytes as a SHA256 hash.
    pub fn new(data: &[u8]) -> Label {
        Label::from_hash(data)
    }

    /// `random` creates a new random `Label`.
    pub fn random() -> Result<Label> {
        let ba = BitArray256::random()?;
        let label = Label(ba);
        Ok(label)
    }

    /// `from_rng` creates a new random `Label` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<Label>
        where R: RngCore
    {
        let ba = BitArray256::from_rng(rng)?;
        let label = Label(ba);
        Ok(label)
    }

    /// `from_hash` creates a `Label` from a SHA256 hash of a slice of bytes.
    pub fn from_hash(data: &[u8]) -> Label {
        let mut hash = [0u8; 32];
        for (i, v) in Sha256::digest(data).as_slice().iter().enumerate() {
            hash[i] = *v;
        }
        Label::from_bytes(hash)
    }

    /// `from_bytes` creates a `Label` from an array of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Label {
        let ba = BitArray256::from_bytes(buf);
        Label(ba)
    }

    /// `to_bytes` converts the `Label` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `from_bitarray` creates a `Label` from a `BitArray256`.
    pub fn from_bitarray(buf: BitArray256) -> Label {
       Label(buf)
    }

    /// `to_bitarray` converts the `Label` to a `BitArray256`.
    pub fn to_bitarray(&self) -> BitArray256 {
        self.0.clone()
    }

    /// `from_node_data` creates a new `Label` from `Node` fields.
    pub fn from_node_data(nonce: u32,
                          op: &Op,
                          value: Option<Value>) -> Result<Label>
    {
        let mut buf = Vec::new();

        op.validate()?;

        let nonce_buf: [u8; 4] = unsafe {
            std::mem::transmute::<u32, [u8; 4]>(nonce)
        };

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
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Op {
    Add { a: Box<Label>, b: Box<Label>, c: Box<Label> },
    Mul { a: Box<Label>, b: Box<Label>, c: Box<Label> },
    Io  { a: Box<Label>, b: Box<Label>, c: Box<Label> },
    Idx { a: Box<Label> },
}

impl Op {
    /// `ADD_CODE` is the code of the Add `Op`.
    const ADD_CODE: u8 = 0x0;

    /// `MUL_CODE` is the code of the Mul `Op`.
    const MUL_CODE: u8 = 0x1;

    /// `IO_CODE` is the code of the Io `Op`.
    const IO_CODE: u8 = 0x2;

    /// `IDX_CODE` is the code of the Idx `Op`.
    const IDX_CODE: u8 = 0x3;

    /// `new_add` creates a new Add `Op`.
    pub fn new_add(a: &Label, b: &Label, c: &Label) -> Result<Op> {
        if (a == b) || (a == c) || (b == c) {
            let msg = "labels are not distinct";
            let source = None;
            let err = Error::new_op(msg, source);
            return Err(err);
        }

        let op = Op::Add {
            a: Box::new(a.to_owned()),
            b: Box::new(b.to_owned()),
            c: Box::new(c.to_owned()),
        };

        Ok(op)
    }

    /// `random_add` creates a random Add `Op`.
    pub fn random_add() -> Result<Op> {
        let a = Label::random()?;
        let b = Label::random()?;
        let c = Label::random()?;

        Op::new_add(&a, &b, &c)
    }

    /// `random_add_from_rng` creates a random Add `Op` from a RNG.
    pub fn random_add_from_rng<R>(rng: &mut R) -> Result<Op>
        where R: RngCore
    {
        let a = Label::from_rng(rng)?;
        let b = Label::from_rng(rng)?;
        let c = Label::from_rng(rng)?;

        Op::new_add(&a, &b, &c)
    }

    /// `to_add_bytes` converts the Add `Op` to a vector of bytes.
    pub fn to_add_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Add { a, b, c } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();
                let b_buf = b.to_bytes();
                let c_buf = c.to_bytes();

                buf.push(Op::ADD_CODE);
                buf.extend_from_slice(&a_buf[..]);
                buf.extend_from_slice(&b_buf[..]);
                buf.extend_from_slice(&c_buf[..]);

                Ok(buf)
            },
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `from_add_bytes` creates an Add `Op` from a slice of bytes.
    pub fn from_add_bytes(buf: &[u8]) -> Result<Op> {
        unreachable!()
    }

    /// `new_mul` creates a new Mul `Op`.
    pub fn new_mul(a: &Label, b: &Label, c: &Label) -> Result<Op> {
        if (a == b) || (a == c) || (b == c) {
            let msg = "labels are not distinct";
            let source = None;
            let err = Error::new_op(msg, source);
            return Err(err);
        }

        let op = Op::Mul {
            a: Box::new(a.to_owned()),
            b: Box::new(b.to_owned()),
            c: Box::new(c.to_owned()),
        };

        Ok(op)
    }

    /// `random_mul` creates a random Mul `Op`.
    pub fn random_mul() -> Result<Op> {
        let a = Label::random()?;
        let b = Label::random()?;
        let c = Label::random()?;

        Op::new_mul(&a, &b, &c)
    }

    /// `random_mul_from_rng` creates a random Mul `Op` from a RNG.
    pub fn random_mul_from_rng<R>(rng: &mut R) -> Result<Op>
        where R: RngCore
    {
        let a = Label::from_rng(rng)?;
        let b = Label::from_rng(rng)?;
        let c = Label::from_rng(rng)?;

        Op::new_mul(&a, &b, &c)
    }

    /// `to_mul_bytes` converts the Mul `Op` to a vector of bytes.
    pub fn to_mul_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Mul { a, b, c } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();
                let b_buf = b.to_bytes();
                let c_buf = c.to_bytes();

                buf.push(Op::MUL_CODE);
                buf.extend_from_slice(&a_buf[..]);
                buf.extend_from_slice(&b_buf[..]);
                buf.extend_from_slice(&c_buf[..]);

                Ok(buf)
            },
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `from_mul_bytes` creates an Mul `Op` from a slice of bytes.
    pub fn from_mul_bytes(buf: &[u8]) -> Result<Op> {
        unreachable!()
    }

    /// `new_io` creates a new Io `Op`.
    pub fn new_io(a: &Label, b: &Label, c: &Label) -> Result<Op> {
        if (a == b) || (a == c) || (b == c) {
            let msg = "labels are not distinct";
            let source = None;
            let err = Error::new_op(msg, source);
            return Err(err);
        }

        let op = Op::Io {
            a: Box::new(a.to_owned()),
            b: Box::new(b.to_owned()),
            c: Box::new(c.to_owned()),
        };

        Ok(op)
    }

    /// `random_io` creates a random Io `Op`.
    pub fn random_io() -> Result<Op> {
        let a = Label::random()?;
        let b = Label::random()?;
        let c = Label::random()?;

        Op::new_io(&a, &b, &c)
    }

    /// `random_io_from_rng` creates a random Io `Op` from a RNG.
    pub fn random_io_from_rng<R>(rng: &mut R) -> Result<Op>
        where R: RngCore
    {
        let a = Label::from_rng(rng)?;
        let b = Label::from_rng(rng)?;
        let c = Label::from_rng(rng)?;

        Op::new_io(&a, &b, &c)
    }

    /// `to_io_bytes` converts the Io `Op` to a vector of bytes.
    pub fn to_io_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Io { a, b, c } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();
                let b_buf = b.to_bytes();
                let c_buf = c.to_bytes();

                buf.push(Op::IO_CODE);
                buf.extend_from_slice(&a_buf[..]);
                buf.extend_from_slice(&b_buf[..]);
                buf.extend_from_slice(&c_buf[..]);

                Ok(buf)
            },
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `from_io_bytes` creates an Io `Op` from a slice of bytes.
    pub fn from_io_bytes(buf: &[u8]) -> Result<Op> {
        unreachable!()
    }

    /// `new_idx` creates a new Idx `Op`.
    pub fn new_idx(a: &Label) -> Op {
        Op::Idx { a: Box::new(a.to_owned()) }
    }

    /// `random_idx` creates a random Idx `Op`.
    pub fn random_idx() -> Result<Op> {
        let a = Label::random()?;
        let op = Op::new_idx(&a);

        Ok(op)
    }

    /// `random_idx_from_rng` creates a random Idx `Op` from a RNG.
    pub fn random_idx_from_rng<R>(rng: &mut R) -> Result<Op>
        where R: RngCore
    {
        let a = Label::from_rng(rng)?;
        let op = Op::new_idx(&a);

        Ok(op)
    }

    /// `to_idx_bytes` converts the Idx `Op` to a vector of bytes.
    pub fn to_idx_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;

        match self {
            Op::Idx { a } => {
                let mut buf = Vec::new();

                let a_buf = a.to_bytes();

                buf.push(Op::IDX_CODE);
                buf.extend_from_slice(&a_buf[..]);

                Ok(buf)
            },
            _ => {
                let err = Error::new_op("invalid op", None);
                Err(err)
            }
        }
    }

    /// `from_idx_bytes` creates an Idx `Op` from a slice of bytes.
    pub fn from_idx_bytes(buf: &[u8]) -> Result<Op> {
        unreachable!()
    }

    /// `random` creates a random `Op`.
    pub fn random() -> Result<Op> {
        let idx = random_u32()?;

        if idx >= idx * 3/4 {
            Op::random_add()
        } else if idx >= idx / 2 {
            Op::random_mul()
        } else if idx >= idx / 4 {
            Op::random_io()
        } else {
            Op::random_idx()
        }
    }

    /// `from_rng` creates a random `Op` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<Op>
        where R: RngCore
    {
        let idx = random_u32()?;

        if idx >= idx * 3/4 {
            Op::random_add_from_rng(rng)
        } else if idx >= idx / 2 {
            Op::random_mul_from_rng(rng)
        } else if idx >= idx / 4 {
            Op::random_io_from_rng(rng)
        } else {
            Op::random_idx_from_rng(rng)
        }
    }

    /// `to_bytes` converts the `Op` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Op::Add { .. } => self.to_add_bytes(),
            Op::Mul { .. } => self.to_mul_bytes(),
            Op::Io { .. } => self.to_io_bytes(),
            Op::Idx { .. } => self.to_idx_bytes(),
        }
    }

    /// `from_bytes` creates an `Op` from a slice of bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Op> {
        unreachable!()
    }

    /// `validate` validates an `Op`.
    pub fn validate(&self) -> Result<()> {
        match self {
            Op::Add { a, b, c } |
            Op::Mul { a, b, c } |
            Op::Io  { a, b, c } => {
                if (*a == *b) || (*a == *c) || (*b == *c) {
                    let msg = "labels are not distinct";
                    let source = None;
                    let err = Error::new_op(msg, source);
                    Err(err)
                } else {
                    Ok(())
                }
            },
            _ => Ok(())
        }
    }
}

impl Default for Op {
    fn default() -> Op {
        Op::Idx { a: Box::new(Label::default()) }
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

        let mut c = Label::random().unwrap();
        while (c == a) || (c == b) {
            c = Label::random().unwrap();
        }

        let res = Op::new_add(&a, &b, &c);
        assert!(res.is_ok());

        let valid_op = res.unwrap();
        let res = valid_op.validate();
        assert!(res.is_ok());

        let invalid_op = Op::Add {
            a: Box::new(a.clone()),
            b: Box::new(b.clone()),
            c: Box::new(b.clone()),
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

        let mut c = Label::random().unwrap();
        while (c == a) || (c == b) {
            c = Label::random().unwrap();
        }

        let res = Op::new_mul(&a, &b, &c);
        assert!(res.is_ok());

        let valid_op = res.unwrap();
        let res = valid_op.validate();
        assert!(res.is_ok());

        let invalid_op = Op::Mul {
            a: Box::new(a.clone()),
            b: Box::new(b.clone()),
            c: Box::new(b.clone()),
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
    }
}

#[test]
fn test_op_new_io() {
    for _ in 0..10 {
        let a = Label::random().unwrap();

        let mut b = Label::random().unwrap();
        while b == a {
            b = Label::random().unwrap();
        }

        let mut c = Label::random().unwrap();
        while (c == a) || (c == b) {
            c = Label::random().unwrap();
        }

        let res = Op::new_io(&a, &b, &c);
        assert!(res.is_ok());

        let valid_op = res.unwrap();
        let res = valid_op.validate();
        assert!(res.is_ok());

        let invalid_op = Op::Io {
            a: Box::new(a.clone()),
            b: Box::new(b.clone()),
            c: Box::new(b.clone()),
        };
        let res = invalid_op.validate();
        assert!(res.is_err());
    }
}

#[test]
fn test_op_random_io() {
    for _ in 0..10 {
        let op = Op::random_io().unwrap();
        let res = op.validate();
        assert!(res.is_ok());
    }
}

#[test]
fn test_op_validate() {
    for _ in 0..10 {
        let valid_add = Op::random_add().unwrap();
        let valid_mul = Op::random_mul().unwrap();
        let valid_io = Op::random_io().unwrap();
        let valid_idx = Op::random_idx().unwrap();

        let res = valid_add.validate();
        assert!(res.is_ok());

        let res = valid_mul.validate();
        assert!(res.is_ok());

        let res = valid_io.validate();
        assert!(res.is_ok());

        let res = valid_idx.validate();
        assert!(res.is_ok());

        let label = Label::random().unwrap();
        let mut other_label = Label::random().unwrap();
        while other_label == label {
            other_label = Label::random().unwrap();
        }

        let invalid_add = Op::Add {
            a: Box::new(label.clone()),
            b: Box::new(label.clone()),
            c: Box::new(other_label.clone()),
        };

        let res = invalid_add.validate();
        assert!(res.is_err());

        let invalid_mul = Op::Mul {
            a: Box::new(label.clone()),
            b: Box::new(label.clone()),
            c: Box::new(other_label.clone()),
        };

        let res = invalid_mul.validate();
        assert!(res.is_err());

        let invalid_io = Op::Io {
            a: Box::new(label.clone()),
            b: Box::new(label.clone()),
            c: Box::new(other_label.clone()),
        };

        let res = invalid_io.validate();
        assert!(res.is_err());
    }
}

/// `Node` is a node in the arithmetic circuit in the field of order
/// q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
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

    /// `random` creates a new random `Node`.
    pub fn random() -> Result<Node> {
        let mut rng = OsRng::new()
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::new_io(&msg, source)
            })?;

        Node::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `Node` from a given RNG.
    pub fn from_rng<R>(mut rng: &mut R) -> Result<Node>
        where R: RngCore + CryptoRng
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

/// `Circuit` is an arithmetic circuit in the field of order q = 2^255 -19.
#[derive(Clone, Default, Debug)]
pub struct Circuit {
    pub id: [u8; 32],
    pub public_inputs: Vec<Label>,
    public_inputs_len: u32,
    pub nondet_inputs: Vec<Label>,
    nondet_inputs_len: u32,
    pub public_outputs: Vec<Label>,
    public_outputs_len: u32,
    nodes: HashMap<Label, Node>,
    nodes_len: u32,
}

impl Circuit {
    /// `new` creates a new `Circuit`.
    pub fn new() -> Result<Circuit> {
        let mut circuit = Circuit::default();
        circuit.id = circuit.calc_id()?;

        Ok(circuit)
    }

    /// `calc_id` calculates the `Circuit` id.
    pub fn calc_id(&self) -> Result<[u8; 32]> {
        let buf = self.to_bytes()?;
        let mut id = [0u8; 32];

        for (i, v) in Sha256::digest(&buf).iter().enumerate() {
            id[i] = *v;
        }

        Ok(id)
    }

    /// `to_bytes` converts the `Circuit` to a vector of bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        unreachable!() // TODO
    }

    /// `from_bytes` creates a new `Circuit` from a slice of bytes.
    pub fn from_bytes(_buf: &[u8]) -> Result<Circuit> {
        unreachable!() // TODO
    }

    /// `validate` validates the `Circuit`.
    pub fn validate(&self) -> Result<()> {
        if self.public_inputs.len() != self.public_inputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        if self.nondet_inputs.len() != self.nondet_inputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
        }

        if self.public_outputs.len() != self.public_outputs_len as usize {
            let err = Error::new_circuit("invalid length", None);
            return Err(err);
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
