use generic_array::{ArrayLength, GenericArray};
use curve25519_dalek::scalar::Scalar;
use std::hash::Hash;
use std::collections::HashMap;

/// `Value` is the a value in the field of order q = 2^255 -19.
#[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
pub struct Value(Scalar);

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
