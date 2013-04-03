(*
	The join protocol.

	We assume that before we start, the issuer and the cryptocard
	have authenticated one another and established a secure
	channel. The issuer knows its talking to a legitimate
	cryptocard and vice versa. Messages arriving at the card are
	authentic. (The DAA paper suggests the issuer might encrypt
	the messages it sends using a TPM's endorsement key.)

	In the following discussion, we suppress details related to
	rogue tags. Please see ./rogue.mli for discussion.

	To see what's going on, consider the Camenisch and Lysyanskaya
	signature scheme for blocks of two messages. (See ./clsig.ml
	for more information on CL.)

	• A CL public key comprises a special RSA modulus [n] and
	bases [R₀], [R₁], [S], and [Z] in some RSA group.

	• A CL signature over the message block [f₀, f₁] comprises a
	random prime [e], a random string [v], and a value [A]
	satisfying
(1)		[A^e ≡ R₀^{f₀} R₁^{f₁} S^v Z	(mod n)].

	• To check the signature [e,v,A] against the message block
	[f₀,f₁], one computes
		[A'₁ := A^e mod n]
	and
		[A'₂ := R₀^{f₀} R₁^{f₁} S^v Z mod n]
	and checks if they're equal. (To create the signature means
	finding [A] and requires either the secret key or the ability
	to solve the RSA problem.)

	The DAA analog to a CL signature [e,v,A] over message block
	[f₀,f₁] is a DAA certificate [e,A] over a secret [f₀,f₁,v].

	In the join protocol, an issuer and a cryptocard conspire to
	produce such a certificate. The protocol using blinding
	factors to prevent the issuer from learning the cryptocard's
	secrets and zero-knowledge proofs to prevent adversarial
	issuers/cryptocards from interfering with the scheme's
	security properties.

	The issuer receives the value
	
		[U = R₀^{f₀} R₁^{f₁} S^{v'} mod n]
	
	containing a blinding factor v'; picks a random prime [e] and
	random value [\hat{v}]; computes the unblinding factor

		v'' := \hat{v} + 2^{ℓ_v - 1}

	and sends the values

		[A := (Z / (U S^{v''}))^{1/e} mod n]
	
	and v'' to the cryptocard. Thus,
	
		A^e ≡ Z / (U S^{v''})	(mod n)
	⇔	A^e ≡ Z / (R₀^{f₀} R₁^{f₁} S^{v'} S^{v''})	(mod n)
	⇔
(2)		A^e ≡ R₀^{-f₀} R₁^{-f₁} S^{-(v'+v'')} Z	(mod n)
	⇔
(3)		Z ≡ A^e R₀^{f₀} R₁^{f₁} S^{v'+v''}	(mod n)
	
	Note the similarity between (1) and (2).

	The cryptocard saves the secret v := v' + v'' along with its
	secrets f₀ and f₁, effectively unblinding the issuer's
	certificate.
*)

(**
	C → I:	U, N_I
	
	U is the cryptocard's blinded key and N_I its rogue tag (cf.
	Steps 1–4 in the DAA paper).
*)
module Join: sig
  type t

  val join: ?rng: Cryptokit.Random.rng ->
    group: Group.pubkey -> rogue: Rogue.key ->
    pk': string ->	(* issuer's long-term public key *)
    bsn: string ->	(* issuer's log-term basename *)
    t * Nat.nat * Nat.nat	(* state, U, N_I *)

end

(**
	C ← I:	n_i

	The issuer aborts if it thinks it's talking to a rogue;
	otherwise, it sends a nonce for use in the card's proof (Steps
	5, 6b).
*)
module Joinreply: sig
  type t

  val reply: ?rng: Cryptokit.Random.rng ->
    group: Group.key -> rogue: Rogue.key ->
    bsn: string ->	(* issuer's basename *)
    bigu: Nat.nat -> bign_I: Nat.nat ->
    t * Nat.nat	(* state, n_i *)
end

(**
	C → I:	proof, n_h
	
	Proof shows that the card knows values making U and N_I
	well-formed (Step 6):
	
	SPK{ (f₀,f₁,v'):
		U ≡ ±R₀^{f₀} R₁^{f₁} S^{v'} (mod n) ∧
		N_I ≡ ζ_I^{f₀+f₁2^{ℓ_f}} (mod Γ) ∧
		f₀,f₁ ∈ {0,1}^{ℓ_f+ℓ_∅+ℓ_H+2} ∧
		v' ∈ {0,1}^{ℓ_n+ℓ_∅+ℓ_H+2) }(n_t || n_i).

	The card sends a nonce for use in the issuer's proof (Step
	8a).

	The issuer checks the card's proof.
*)
module Provejoin: sig

  type response = { sf0: Nat.nat; sf1: Nat.nat; sv': Nat.nat }
  type proof = string * Nat.nat * response	(* c, n_t, responses *)

  val prove: ?rng: Cryptokit.Random.rng ->
    state: Join.t ->
    n_i: Nat.nat ->
    proof * Nat.nat	(* proof, n_h *)

  val check: state: Joinreply.t -> proof -> unit

end

(*
	C ← I:	proof', (A,e), v''
	
	The issuer constructs a certificate (A,e) over U, an
	unblinding factor v'', and a proof showing that the issuer
	knows values making A well-formed:
	
	SPK{ (d): A ≡ ±(Z/(US^{v''}))^d (mod n) }(n_h).

	If everything checks out, the card removes the blinds to
	obtain a certificate (A,e) over its secret (f₀,f₁,v), where
		v := v' + v''.
	(Steps 8b-10.)
*)
module Sign: sig

  type proof = { c': string; s_e: Nat.nat }
  
  val sign: ?rng: Cryptokit.Random.rng ->
    state: Joinreply.t -> n_h: Nat.nat ->
    proof * Group.cert * Nat.nat	(* proof', cert, v'' *)
  
  val check:
    state: Join.t ->
    proof:proof -> cert:Group.cert -> v'':Nat.nat ->
    Group.secret
  (**
	Raises an exception if anything is invalid.
  *)
end
