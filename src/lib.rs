use typenum::marker_traits::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use curve25519_dalek::scalar::Scalar;
use std::hash::Hash;
use std::collections::HashMap;

/// `BitArray` is an array of bits.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct BitArray<N>(GenericArray<u8, N>)
    where N: ArrayLength<u8>;

/// `Degree` is the degree of a monomial or a polynomial.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Degree<D: Unsigned>(D);

/// `Value` is the a value in the field of order q = 2^255 -19.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct Value(Scalar);

/// `Variable` is a monomial in the field of order q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Variable<D>
    where D: Unsigned
{
    pub degree: Degree<D>,
    pub coefficient: Value,
    pub value: Option<Value>,
}

/// `Vector` is a vector of values in the field of order q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Vector<N>(GenericArray<Value, N>)
    where N: ArrayLength<Value>;

/// `Polynomial` is a of variables in the field of order q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Polynomial<D, N>
    where D: Unsigned,
          N: ArrayLength<Variable<D>>,
{
    pub degree: Degree<D>,
    pub variables: GenericArray<Variable<D>, N>
}

/// `Label` is a label of a node in the circuit.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Label<S>(BitArray<S>)
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>;

/// `Labels` is an array of labels of nodes in a Spartan arithmetic circuit.
#[derive(Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Labels<S, L>(GenericArray<Label<S>, L>)
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>,
          L: ArrayLength<Label<S>>;

/// `Op` is an arithmetic circuit operation.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Op<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>,
{
    Add { a: Label<S>, b: Label<S>, c: Label<S> },
    Mul { a: Label<S>, b: Label<S>, c: Label<S> },
    IO  { a: Label<S>, b: Label<S>, c: Label<S> },
    Idx { a: Label<S> },
}

impl<S> Default for Op<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>,
{
    fn default() -> Op<S> {
        Op::Idx { a: Label::default() }
    }
}

/// `Node` is a node in the arithmetic circuit in the field of order
/// q = 2^255 -19.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Node<S>
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>,
{
    pub label: Label<S>,
    pub op: Op<S>,
    pub value: Option<Value>,
}

/// `Circuit` is an arithmetic circuit in the field of order q = 2^255 -19.
#[derive(Clone, Default, Debug)]
pub struct Circuit<S, P, Q, R>
    where S: Default + Eq + Ord + Hash + ArrayLength<u8>,
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
