use generic_array::{ArrayLength, GenericArray};
use curve25519_dalek::scalar::Scalar;
use rand_core::{RngCore, CryptoRng};
use rand_os::OsRng;
use std::hash::Hash;
use std::collections::HashMap;
use std::fmt;
use std::error;
use std::result;

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
}

/// `BitArray` is an array of bits.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct BitArray<N>(GenericArray<bool, N>)
    where N: ArrayLength<bool>;

/// `Label` is a label of a node in the circuit.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Label<S>(BitArray<S>)
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>;

/// `Labels` is an array of labels of nodes in a Spartan arithmetic circuit.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Labels<S, L>(GenericArray<Label<S>, L>)
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>,
          L: ArrayLength<Label<S>>;

/// `Op` is an arithmetic circuit operation.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Op<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>,
{
    Add { a: Label<S>, b: Label<S>, c: Label<S> },
    Mul { a: Label<S>, b: Label<S>, c: Label<S> },
    IO  { a: Label<S>, b: Label<S>, c: Label<S> },
    Idx { a: Label<S> },
}

impl<S> Default for Op<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>,
{
    fn default() -> Op<S> {
        Op::Idx { a: Label::default() }
    }
}

/// `Node` is a node in the arithmetic circuit in the field of order
/// q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Node<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>,
{
    pub label: Label<S>,
    pub op: Op<S>,
    pub value: Option<Value>,
}

/// `Circuit` is an arithmetic circuit in the field of order q = 2^255 -19.
#[derive(Clone, Default, Debug)]
pub struct Circuit<S, P, Q, R>
    where S: Default + Eq + Ord + Hash + ArrayLength<bool>,
          P: ArrayLength<Label<S>>,
          Q: ArrayLength<Label<S>>,
          R: ArrayLength<Label<S>>,
{
    pub public_inputs: Labels<S, P>,
    pub nondet_inputs: Labels<S, Q>,
    pub public_outputs: Labels<S, R>,
    nodes: HashMap<Label<S>, Node<S>>,
    length: u32,
}
