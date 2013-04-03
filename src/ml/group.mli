(** DAA's variant of the CL signature scheme. *)

(**
	Issuer public keys comprise parameters for the group signature
	scheme.
*)
type pubkey =
  { n: Nat.nat;
    g': Nat.nat;	(** <g'> = QR_n *)
    (* Bases: g,h ∈ <g'>; s,z ∈ <h>; and r0,r1 ∈ <s>. *)
    g: Nat.nat; h: Nat.nat; s: Nat.nat; z: Nat.nat; r0: Nat.nat; r1: Nat.nat;
    proof: Provelog.proof }

(**
	Issuer private keys.
*)
type key = { pub: pubkey; p'q': Nat.nat }

val new_key: ?rng: Cryptokit.Random.rng -> unit -> key
val pubkey: key -> pubkey
val check_key : pubkey -> unit

(**
	Cryptocard secrets and the corresponding certs.
*)
type cert = { biga: Nat.nat; e: Nat.nat }
type secret = { f0: Nat.nat; f1: Nat.nat; v: Nat.nat }
