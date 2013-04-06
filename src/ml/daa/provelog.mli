(**
	Proof of knowledge of a list of discrete logarithms modulo a
	composite.
	
		SPK{ (α₁,…,α_k):
			g₁ = h₁^{α₁} mod n ∧ ⋯ ∧
			g_k = h_k^{α_k} mod n }.

	Based on Appendix A in the full version of the DAA paper.
	
	Alleged security properties: Satistical witness
	indistinguishable and soundness (by reduction to the flexible
	RSA problem in the random oracle model).

	PDS: I have not settled on a satisfying reference for this
	scheme, so I'll be more verbose than I'd like. I will neither
	define the security properties I care about nor attempt a
	proof. I will offer some intuitions. At the end, I will offer
	some pointers to the literature.

	— The problem
	
	Let the group G and g, h ∈ G be given. Suppose a prover P and
	verifier V agree on G, g, h and P wants to convince V that

		∃α. α = log_h g
	⇔	∃α. h^α = g
	⇔	g ∈ <h>

	without revealing the witness α.

	— Making the verifier happy: Basic protocol

	Consider the following protocol. It has the form “commit,
	challenge, response” (a so-called Σ-protocol).
	
		P → V:	t := h^r	(for r ≥ 1 fresh)
		P ← V:	b	(for b ∈ {0,1} fresh)
		P → V:	s := r - bα

	After running the protocol, the verifier knows t, b, and s
	and so can check
		t =? g^b h^s.

	From the verifier's perspective, the protocol is great. The
	point:
		t = g^b h^s
	⇔	h^r = g^b h^{r - bα}
	⇔	r = b log_h g + r - bα
	⇔	bα = b log_h g
	⇔	b = 0 ∨
		(b = 1 ∧ α = log_h g).

	Thus a prover cannot answer both challenges b = 0 and b = 1
	correctly without knowing log_h g. Intuitively, the protocol
	satisfies /soundness/. If a (potentially adversarial) prover
	survives k runs of the protocol, then with probability 2^{-k},
	the prover knows log_h g.

	— Making the prover happy: An RSA group
	
	Here's another intuition: A protocol satisfies /witness
	indistinguishability/ if there exists a simulator for the
	prover such that (a) the simulator doesn't know the prover's
	secrets and yet (b) the distribution of “conversations”
	between the verifier and the prover matches the distribution
	of conversations between the verifier and the simulator.

	If we could restrict our parameters G, g, and h in order to
	deny a (potentially adversarial) verifier any “computational
	back doors” to the prover's secret α, then we might attempt to
	prove our protocol satisfies WI.
	
	We restrict our parameters as follows.
	
		G = ℤ∗_n ∧
		<h> = QR_n

	where n is a special RSA modulus; in particular, there exist
	primes p, p', q, q' satisfying
	
		n = pq ∧
		p = 2p' + 1 ∧ q = 2q' + 1 ∧ q ≠ p.
	
	So that |QR_n| = p'q'. Our protocol specializes to
	
		P → V:	t := h^r mod n	(for r ∈ {1,…,p'q'} fresh)
		P ← V:	b	(for b ∈ {0,1} fresh)
		P → V:	s := (r - bα) mod p'q'.

	where the verifier computes
		v := g^b h^s mod n

	and checks
		t =? v.

	Now our imaginary proofs can argue that no such “computational
	back doors” exists by reduction to the strong RSA assumption.

	— Making the protocol practical: Avoiding communication

	We apply the so-called Fiat-Shamir heuristic to avoid
	communication between the prover and the verifier.

	The prover picks ℓ_H random values, computes the corresponding
	commitments, hits the common inputs and those commitments with
	a hash function H, then computes ℓ_H responses using bits from
	the hash as challenges. In practical terms, the prover hopes
	that no adversarial verifier can defeat H to discover
	computational back doors to α. Now our imaginary proofs must
	make the random oracle assumption, in addition to the strong
	RSA assumption.

	One final wrinkle: We lift the basic protocol to a list of
	logarithms with distinct bases (that share a common generator
	<h> = QR_n). The resulting scheme matches that used in the DAA
	paper's Appendix A.

	— References

	On cursory inspection, I believe this is the bit commitment
	scheme in §3.1 of

		Fujisaki and Okamoto.
		Statistical zero knowledge protocols to prove
		modular polynomial relations.
		Crypto '97.
		doi:10.1007/BFb0052225
	
	I can recommend three introductions to zero-knowledge
	protocols.

	1. Read Chapters 4 and 5 in Berry Schoenmakers' excellent
	lecture notes “Cryptographic Protocols”. (The chapter numbers
	come from the February 4, 2013 version of those notes.)
	
	2. Read
	
		Bellare and Goldreich.
		On defining proofs of knowledge.
		Crypto '92.
		doi:10.1007/3-540-48071-4_28
	
	and then read Ivan Damgård's lecture notes “On Σ-protocols”.

	3. Read Chapter 10 in Menezes et al.'s “Handbook of Applied
	Cryptography” (available online). (I mention this mainly
	because the handbook has proven useful to me for other
	things.)
*)

type proof = string * Nat.nat list list	(* c,rs *)
(**
	If (c,rs) : proof, then [c] contains [hash_bits] challenge
	bits (in big-endian byte order) and rs = [rs₁,…,rs_k]
	where [rs_i] lists the [hash_bits] responses
	for this proof's [i]th logarithm.
*)

val prove: ?rng: Cryptokit.Random.rng ->
  n: Nat.nat -> g': Nat.nat ->	(* public *)
  gs: Nat.nat list -> hs: Nat.nat list ->	(* public *)
  alphas: Nat.nat list -> p'q': Nat.nat ->	(* private *)
  proof
(**
	Consider [prove ~n ~g' ~gs ~hs ~alphas ~p'q'] where
		gs = [g₁; ⋯; g_k] ∧
		hs = [h₁; ⋯; h_k] ∧
		alphas = [α₁; ⋯; α_k].

	If <g'> = QR_n
	and |QR_n| = p'q'
	and for each i, g_i = h_i^{α_i} mod n
	and each h_i is either g' or some h_j for j < i,
	then prove constructs
		SPK{ (α₁,…,α_k):
			g₁ = h₁^{α₁} mod n ∧ ⋯ ∧
			g_k = h_k^{α_k} mod n }.
*)

val check:
  n:Nat.nat -> g':Nat.nat ->
  gs: Nat.nat list -> hs: Nat.nat list ->
  proof -> unit
