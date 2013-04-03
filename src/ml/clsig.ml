(**
	Camenisch and Lysyanskaya signature scheme.
	
	Security property: Unforgeability (by reduction to the
	flexible RSA problem).

	A key comprises a special RSA modulus [n], one of its prime
	factors [p], and members [a₁], …, [a_L], [b], and [c] of QR_n
	where [L] is the parameter [messages_per_block]. All but [p]
	are public.

	A signature for a block of messages [m₁; …; m_L] and a key as
	above comprises a random prime [e], a random string [s], and a
	value [v] satisfying
		[v^e = a₁^{m₁} ⋯ a_L^{m_L} b^s c mod n].

	See
		Camenisch and Lysyanskaya.
		A signature scheme with efficient protocols.
		SCN, 2002.
		doi:10.1007/3-540-36413-7_20
*)

module type PARM = sig

  val messages_per_block: int
  (**
	[messages_per_block] (nee L) is the number of
	[message_bits]-bit messages covered by each signature.
  *)

  val rsa_modulus_bits: int
  (**
	[rsa_modulus_bits] (nee ℓ_n) is the length in bits of the
	signer's special RSA modulus. We require that
	[rsa_modulus_bits] be even.
  *)

  val message_bits: int
  (** [message_bits] (nee ℓ_m) is the length in bits of messages. *)

  val reduction_bits: int
  (**
	[reduction_bits] (nee ℓ) is used in the reduction from an
	algorithm to forge signatures to an algorithm to solve the
	flexible RSA problem. It should be on the order of
	message_bits.

	See the paper, Lemma 3.
  *)

  val prime_bits: int
  (**
	[prime_bits] (nee ℓ_e) is the length in bits of the random
	primes used in signatures. We require that [prime_bits >=
	message_bits + 2].
  *)

end

module type CL = sig

  include PARM
  
  val rsa_factor_bits: int
  (**
	[rsa_factor_bits = rsa_modulus_bits/2] is the length in bits
	of RSA modulus' prime factors.
  *)

  val random_bits: int
  (**
	[random_bits] (nee ℓ_s) is the length in bits of the random
	strings used in signatures.
  *)

  type key = { n: Nat.nat; p: Nat.nat; gs: Nat.nat list; c: Nat.nat }
  (**
	[p] is private and has length [rsa_factor_bits]; everything
	else is public and has length [rsa_modulus_bits]. The base
	list [gs] satisfies
		gs = [b, a₁, …, a_L].
  *)

  type signat = { e: Nat.nat; s: Nat.nat; v: Nat.nat }
  (**
	[e] has length [prime_bits], [s] has length [random_bits], and
	[v] has length [rsa_modulus_bits].
  *)

  val new_key: ?rng: Cryptokit.Random.rng -> ?modulus: Util.Rsa.modulus -> unit -> key
  
  val sign: ?rng: Cryptokit.Random.rng -> key -> string list -> signat
  
  val verify : key -> string list -> signat -> bool
  
end
