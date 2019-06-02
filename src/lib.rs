use typenum::marker_traits::Unsigned;
use generic_array::{ArrayLength, GenericArray};
use curve25519_dalek::scalar::Scalar;
use std::collections::HashMap;

/// `BitArray` is an array of bits.
#[derive(Clone, Default, Eq, PartialEq, Debug)]
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
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Debug, Hash)]
pub struct Label(u8);

/// `Op` is an arithmetic circuit operation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
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
pub struct Circuit<M, Q, N, D>
    where M: ArrayLength<Value>,
          Q: ArrayLength<Value>,
          N: ArrayLength<Value>,
          D: Unsigned,
{
    pub public_inputs: Vector<M>,
    pub nondet_inputs: Vector<Q>,
    pub public_outputs: Vector<N>,
    length: D,
    nodes: HashMap<Label, Node>,
}
