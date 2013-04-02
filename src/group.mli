(** DAA's variant of the CL signature scheme. *)

type pubkey =
  { n: Nat.nat;
    g': Nat.nat;	(** <g'> = QR_n *)
    (* Bases: g,h ∈ <g'>; s,z ∈ <h>; and r0,r1 ∈ <s>. *)
    g: Nat.nat; h: Nat.nat; s: Nat.nat; z: Nat.nat; r0: Nat.nat; r1: Nat.nat;
    proof: Provelog.proof }

type key

type signat

val new_key: ?rng: Cryptokit.Random.rng -> unit -> key

val pubkey: key -> pubkey

val check_key : pubkey -> unit
