exception Error of string
val error : string -> 'a

val memoize: (unit -> 'a) -> unit -> 'a

module Listutil: sig

  val revgen: (unit -> 'a) -> int -> 'a list
  (**
	[revgen f n] runs [f] [n] times, returning the list
		[v_n, …, v₁]
	where [v_i] is the ith value returned by f.
  *)

  val map3: ('a -> 'b -> 'c -> 'd) -> 'a list -> 'b list -> 'c list -> 'd list
  (**
	[map3 f [x₁; ⋯; x_n] [y₁; ⋯; y_n] [z₁; ⋯; z_n]] returns the list
		[f(x₁,y₁,z₁); ⋯; f(x_n,y_n,z_n)].
	It raises an exception if the input lists do not have
	equal lengths.
  *)

end

module Numutil: sig

  val nat_bit: Nat.nat -> int -> bool
  (** [nat_bit n i] returns the ith bit of n. *)

  val string_bit: string -> int -> bool
  (**
	Identical to nat_bit, viewing a string of bytes as a
	big-endian natural number; for example, bit 0 is a string's
	right-most bit.
  *)

  val divides: Nat.nat -> Nat.nat -> bool
  (** [divides a b] is true if a | b. *)

  val mod_mult: Nat.nat -> Nat.nat -> Nat.nat -> Nat.nat
  (** [mod_mult a b n] returns [ab mod n]. *)
  
  val shift_left_nat: Nat.nat -> int -> Nat.nat
  (** [shift_left_nat n i] returns n·2^i. *)

  val random_nat_in: ?rng: Cryptokit.Random.rng -> Nat.nat -> Nat.nat -> unit -> Nat.nat
  (**
	[random_nat_in min max ()] returns a random value in
	{min,…,max}.
  *)
  
  val nat_of_msg: int -> string -> Nat.nat
  (**
	[nat_of_msg maxbits s] converts [s] (a big-endian
	byte array) to a natural number, raising an exception
	if its bit-length exceeds [maxbits].
  *)

end

module Hashutil: sig

  val hash_bytes: (unit -> Cryptokit.hash) -> int
  val hash_bits: (unit -> Cryptokit.hash) -> int
  
  val add_byte: Cryptokit.hash -> int -> unit

  val add_list: (Cryptokit.hash -> 'a -> unit) -> Cryptokit.hash -> 'a list -> unit

  val add_nat: ?numbits: int -> Cryptokit.hash -> Nat.nat -> unit
  (**
	[add_nat h n] sends the bytes of [n] to [h] in big-endian
	order. The function can pad [n] with zero bits on the left:
	The optional argument [numbits] determines how many bytes are
	sent to [h]. It must equal or exceed it's default value, the
	bit-length of [n].
  *)

  val add_nat_list: ?numbits: int -> Cryptokit.hash -> Nat.nat list -> unit
  (**
  	[add_nat_list h [n₁; ⋯; n_k]] sends the [n_i]'s to [h] using
  	[hash_nat].
  *)

  val adjust: (unit -> Cryptokit.hash) -> numbits:int -> Cryptokit.hash
  (**
	If [H'] = [adjust H ~numbits]
	and [H] produces [numbits_H]-bit results,
	and 0 < numbits < 256*numbits_H
	and 8 | numbits,
	then [H'] produces [numbits]-bit results as follows.
	
	On input [m], the hash returns the leftmost [numbits] bits of
		H(0||m) || H(1||m) || ⋯ || H(n||m)
	where [n] is [ceil(numbits/numbits_H)] and each prefix 0, …, n
	is one byte long.
  *)

end

module Rsa: sig

  type modulus
  (**
	A special RSA modulus [n] of length [k] has prime factors [p]
	and [q] satisfying
		n = pq ∧
		2^{k-1} ≤ p, q < 2^k - 1 ∧
		p > q ∧
		p = 2p' + 1 ∧ q = 2q' + 1
	for some primes [p'] and [q'].
	
	The first line requires that [n] be an RSA modulus with
	factors [p] and [q]. The second imposes size restrictions. The
	third orders the factors. (At the moment, none of our code
	assumes that order.) The fourth makes [p] and [q] so-called
	safe primes.
  *)

  val new_special: ?rng: Cryptokit.Random.rng -> ?modulus: modulus -> int -> modulus
  (**
	[new_special k] create or reuse a special RSA modulus of
	length [k]. If the optional [modulus] is specified but does
	not have length [k], then an exception is raised.
  *)

  val size: modulus -> int
  
  (*
	Note that the following projections
	do not make copies.
  *)

  val factors: modulus -> Nat.nat * Nat.nat * Nat.nat
  (** n, p, q *)

  val n: modulus -> Nat.nat
  val p: modulus -> Nat.nat
  val q: modulus -> Nat.nat
  val p': modulus -> Nat.nat
  val q': modulus -> Nat.nat
  val p'q': modulus -> Nat.nat

  val new_QR_n_generator: ?rng: Cryptokit.Random.rng -> modulus -> Nat.nat
  (** Picks a random generator of QR_n. *)

  val new_QR_n_member: ?rng: Cryptokit.Random.rng -> base: Nat.nat -> modulus -> unit -> Nat.nat * Nat.nat
  (**
	Assuming base ∈ QR_n, the function picks a random r ∈
	{1,…,p'q'}, computes g = base^r mod n ∈ <base>, and returns
	(r,g).
  *)

end
