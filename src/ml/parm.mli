val rsa_modulus_bits: int	(* ℓ_n *)
val halfkey_bits: int	(* ℓ_f *)
val prime_total_bits: int	(* ℓ_e *)
val prime_random_bits: int	(* ℓ'_e *)
val random_bits: int	(* ℓ_v *)
val distribution_bits: int	(* ℓ_∅ *)
val hash_bits: int	(* ℓ_H *)
val reduction_bits: int	(* ℓ_r *)
val rogue_modulus_bits: int	(* ℓ_Γ *)
val rogue_security_bits: int	(* ℓ_ρ *)
val rogue_hash_bits: int	(* = ℓ_Γ+ℓ_∅ *)

val new_hash: unit -> Cryptokit.hash	(* length ℓ_H *)
val new_rogue_hash: unit -> Cryptokit.hash	(* length ℓ_Γ+ℓ_∅ *)

(**
	Models a cryptocard's secure storage and identity.
*)
module Storage: sig

  val identity: Nat.nat -> string
  (**
	Given a nonce, return a proof of this cryptocard's identity
	that can be verified by an issuer; for example, sign the nonce
	with some private key backed by cert chain ending with the
	IBM.
  *)

  val daaseed: unit -> string
  (**
	Current value of DAAseed on this cryptocard. In principle, the
	user can force the creation of a fresh DAAseed.
  *)
  
  val get_cnt: unit -> int
  val inc_cnt: unit -> unit
  (**
	DAA join counter. I don't see the point.
  *)

end

(*
	DAA utility functions. There aren't enough of them to justify
	a “Daautil” module.
*)

val join: f0: Nat.nat -> f1: Nat.nat -> Nat.nat
(**
	Combine two ℓ_f-bit halves into a 2ℓ_f-bit whole:
		[join f₀ f₁] = f₀+f₁2^{ℓ_f}.
	In C notation, we compute (f₁<<ℓ_f) | f₀.
*)
