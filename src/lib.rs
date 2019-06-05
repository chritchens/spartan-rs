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

/// `Error` is the library error type.
#[derive(Debug)]
pub enum Error {
    IO { msg: String, source: Option<Box<dyn error::Error + 'static>> },
    Value { msg: String, source: Option<Box<dyn error::Error + 'static>> },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::IO { msg, .. } => write!(f, "IO: {}", msg),
            Error::Value { msg, .. } => write!(f, "Value: {}", msg),
        }
    }
}

/// `Result` is the type used for fallible outputs. It's an
/// alias to the Result type in standard library whith error
/// the library Error type.
pub type Result<T> = result::Result<T, Error>;

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
                Error::IO { msg, source }
            })?;

        BitArray256::from_rng(&mut rng)
    }

    /// `from_rng` creates a new random `BitArray256` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<BitArray256>
        where R: RngCore + CryptoRng
    {
        let mut buf = [0u8; 32];
        rng.try_fill_bytes(&mut buf)
            .map_err(|e| {
                let msg = format!("{}", e);
                let source = Some(Box::new(e) as Box<dyn error::Error + 'static>);
                Error::IO { msg, source }
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
                Error::IO { msg, source }
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
            let msg = "bytes are not canonical".into();
            let source = None;
            let err = Error::Value { msg, source };
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
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Label(BitArray256);

impl Label {
    /// `new` creates a new `BitArray256`.
    pub fn new(v: &Value) -> Label {
        Label::from_value(v)
    }

    /// `random` creates a new random `BitArray256`.
    pub fn random() -> Result<Label> {
        let ba = BitArray256::random()?;
        let label = Label(ba);
        Ok(label)
    }

    /// `from_rng` creates a new random `BitArray256` from a given RNG.
    pub fn from_rng<R>(rng: &mut R) -> Result<Label>
        where R: RngCore + CryptoRng
    {
        let ba = BitArray256::from_rng(rng)?;
        let label = Label(ba);
        Ok(label)
    }

    /// `from_value` creates a `BitArray256` from a `Value`.
    pub fn from_value(v: &Value) -> Label {
        let buf = v.to_bytes();
        Label::from_hash(&buf[..])
    }

    /// `from_hash` creates a `BitArray256` from a SHA256 hash of a slice of bytes.
    pub fn from_hash(buf: &[u8]) -> Label {
        let mut hash = [0u8; 32];
        for (i, v) in Sha256::digest(buf).as_slice().iter().enumerate() {
            hash[i] = *v;
        }
        Label::from_bytes(hash)
    }

    /// `from_bytes` creates a `BitArray256` from an array of bytes.
    pub fn from_bytes(buf: [u8; 32]) -> Label {
        let ba = BitArray256::from_bytes(buf);
        Label(ba)
    }

    /// `to_bytes` converts the `BitArray256` to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `from_bitarray` creates a `Value` from a `BitArray256`.
    pub fn from_bitarray(buf: BitArray256) -> Label {
       Label(buf)
    }

    /// `to_bitarray` converts the `Value` to a `BitArray256`.
    pub fn to_bitarray(&self) -> BitArray256 {
        self.0.clone()
    }
}

#[test]
fn test_label_from_value() {
    for _ in 0..10 {
        let value_a = Value::random().unwrap();
        let value_b = Value::random().unwrap();

        let label_a = Label::from_value(&value_a);
        let label_b = Label::from_value(&value_b);

        if value_a == value_b {
            assert_eq!(label_a, label_b);
        } else {
            assert!(label_a != label_b);
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
/// `Labels` is an array of labels of nodes in a Spartan arithmetic circuit.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Labels<L>(GenericArray<Label, L>)
    where L: ArrayLength<Label>;

/// `Op` is an arithmetic circuit operation.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Op {
    Add { a: Label, b: Label, c: Label },
    Mul { a: Label, b: Label, c: Label },
    IO  { a: Label, b: Label, c: Label },
    Idx { a: Label },
}

impl Default for Op {
    fn default() -> Op {
        Op::Idx { a: Label::default() }
    }
}

/// `Node` is a node in the arithmetic circuit in the field of order
/// q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Node {
    pub label: Label,
    pub op: Op,
    pub value: Option<Value>,
}

/// `Circuit` is an arithmetic circuit in the field of order q = 2^255 -19.
#[derive(Clone, Default, Debug)]
pub struct Circuit<P, Q, R>
    where P: ArrayLength<Label>,
          Q: ArrayLength<Label>,
          R: ArrayLength<Label>,
{
    pub public_inputs: Labels<P>,
    pub nondet_inputs: Labels<Q>,
    pub public_outputs: Labels<R>,
    nodes: HashMap<Label, Node>,
    length: u32,
}
