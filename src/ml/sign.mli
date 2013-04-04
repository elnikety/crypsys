(*
	The cryptocard should sign the message [m], mentioning
	a nonce [n_v]. 
	
	The verifier may provide a basename; for example, an
	implementation might take the verifier's basename to be
	whatever data were used to identify and authenticate the
	verifier. We model this using an optional argument
	?bsn:string.

	The message m may originate with the verifier or with
	Cryptocard itself. In the paper, this is modelled using a
	value [b ∈ {0, 1}]; we write [b : origin].

	Sketch:
		V → C:	m, n_v
		C → V:	σ
*)

type nat = Nat.nat
type big_int = Big_int.big_int

(*
	Messages.
*)
type origin = Card | Verifier
type msg = { bsn: string option; m: string; b: origin; n_v: nat }

(*
	Signatures.
*)
type responses =
  { sv: nat; sf0: nat; sf1: nat;
    se: big_int; see: nat;
    sw: nat; sew: nat;
    sr: nat; ser: nat }

type signat =
  { zeta: nat; bigt1: nat; bigt2: nat; bign_V: nat; c: string; n_t: nat;
    ss: responses }

val sign: ?rng: Cryptokit.Random.rng ->
  group: Group.pubkey -> rogue: Rogue.key ->
  secret: Join.secret -> cert: Join.cert ->
  msg ->
  signat

val verify:
  group: Group.pubkey -> rogue: Rogue.key ->
  msg: msg -> signat -> unit
(*
	Raises an exception on mismatch.
*)
