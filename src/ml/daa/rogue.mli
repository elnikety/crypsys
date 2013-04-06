(*
	DAA pseudonyms and rogue tagging.
	
	During setup, an issuer picks a group G such that the discrete
	logarithm problem in G has about the same difficulty as
	factoring DAA RSA moduli.

	Many issuers and verifiers can share the same rogue-tagging
	group. DAA assigns distinct tags to issuers/verifiers via
	so-called basenames. As far as the protocol is concerned,
	basenames are uninterpreted strings; see §6.2 in [Smyth et
	al., 2012] for practical advice.

	While running the join protocol with an issuer or the signing
	protocol with a verifier that supplies its basename, a
	cryptocard computes a base ζ ∈ G from its peer's name and
	commits to the rogue tag N = ζ^f, where f is the cryptocard's
	secret key for use in DAA signatures. (When signing with a
	verifier that does not supply a basename, the cryptocard picks
	a random ζ ∈ G.)

	A rogue tagging key comprises primes Γ and ρ and a member γ
	of ℤ∗_Γ such that <γ> is a subgroup of order ρ and ρ is a
	large prime factor of Γ - 1:
		∃r ∈ ℕ, γ' ∈ ℤ∗_Γ.
		Γ = rρ + 1 ∧
		ρ ∤ r ∧
		2^{ℓ_Γ - 1} < Γ < 2^{ℓ_Γ} ∧
		2^{ℓ_ρ - 1 < ρ < 2^{ℓ_ρ} ∧
		γ'^r ≢ 1 (mod Γ) ∧
		γ = γ'^r mod Γ.
	All of Γ, ρ, and γ are public.
	
	There are at least two important points to make regarding ℓ_ρ:

	• It's the maximum bit length of cryptocard secrets f.
	
	• It must be chosen large enough to make it difficult to
	compute discrete logarithms in <γ>; see the discussion around
	Algorithm 4.84, “Selecting a k-bit prime p and a generator α
	of ℤ∗_p” in Menezes et al., 1996.

	We offer no “check if this tag is a rogue” heuristic. In
	theory, issuers and verifiers use tags to track legitimate
	users (pseudonymously) and to identify rogues. We offer tags,
	but no heuristics. Each issuer/verifier must settle on a
	policy. (The DAA paper suggests that when talking to a
	platform with tag N, a verifier checks N and any earlier N'
	used by that platform against a blacklist. If found, the
	verifier should abort the protocol.)

	References:

		Brickell, Camenisch, and Chen.
		Direct Anonymous Attestation.
		http://eprint.iacr.org/2004/205
		(Full version of their CCS '04 paper.)

		Smyth, Ryan, and Chen.
		Formal analysis of privacy in Direct Anonymous
		Attestation schemes.
		http://eprint.iacr.org/2012/650
	
		Menezes, van Oorschot, and Vanstone.
		Handbook of Applied Cryptography.
		CRC Press, 1996.
		http://cacr.uwaterloo.ca/hac/
*)

type key = { biggamma: Nat.nat; rho: Nat.nat; gamma: Nat.nat }

val new_key: ?rng: Cryptokit.Random.rng -> unit -> key

val check_key: key -> unit
(**
	Check that Γ and ρ are primes with lengths ℓ_Γ and
	ℓ_ρ that satisfy
		ρ ∣ (Γ - 1) ∧
		ρ ∤ (Γ - 1)/ρ ∧
		γ^ρ ≡ 1 (mod Γ).
	If not, raise Error.
*)

val valid: key -> Nat.nat -> bool
(**
	[valid key v] returns true if [v ∈ <γ>]; that is, if [1 ≡ v^ρ
	(mod Γ)]. Values obtained using [key] with Rogue.base and
	Rogue.tag are valid provided [key] is well-formed.)
*)

val base: ?rng: Cryptokit.Random.rng -> ?bsn: string -> key -> Nat.nat
(**
	If the optional [bsn] is provided, then compute
	the value
		ζ = (H_Γ(1||bsn))^{(Γ-1)/ρ} mod Γ
	where the hashed 1 represents a single byte; otherwise, pick a
	random
		ζ ∈ <γ>.
	If this value satisfies
		ζ^ρ ≡ 1 (mod Γ),
	then return it; otherwise, raise Error.
*)

val tag: key -> zeta: Nat.nat ->
  f0: Nat.nat -> f1: Nat.nat ->	(* private *)
  Nat.nat
(**
	Compute the rogue tag for use with our peer with base ζ:
		N = ζ^f mod Γ
	where f = f₀ + f₁·2^{ℓ_f}.
*)
