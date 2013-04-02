let error = Util.error
let hash_bits = Parm.hash_bits
module Bn = Cryptokit.Bn
module Hashutil = Util.Hashutil
module Listutil = Util.Listutil
module Numutil = Util.Numutil
module Rsa = Util.Rsa
type nat = Nat.nat

(*
	One log, one challenge.
*)

(** Pick an r ∈ {1,…,p'q'}. *)
let bit_rand ?rng ~p'q' : unit -> nat =
  Numutil.random_nat_in ?rng Bn.one p'q'

(** Compute t = h^r mod n *)
let bit_commit ~n ~h (r:nat) : nat =
  Bn.mod_power h r n

(** Compute s = (r - bα) mod p'q' *)
let bit_respond ~p'q' ~alpha (r:nat) (b:bool) : nat =
  if b then Bn.sub_mod r alpha p'q' else Bn.mod_ r p'q'

(** Compute v = g^b h^s mod n *)
let bit_checksum ~n ~h ~g (b:bool) (s:nat) : nat =
  let v = Bn.mod_power h s n in
  if b then Numutil.mod_mult g v n else v

(**
	One log, all challenges.
*)

let log_rand ?rng ~p'q' : nat list =
  Listutil.revgen (bit_rand ?rng ~p'q') hash_bits

let log_commit ~n (h:nat) (rs:nat list) : nat list =
  List.map (bit_commit ~n ~h) rs

let log_respond ~p'q' (b:string) (alpha:nat) (rs:nat list) : nat list =
  let ith_challenge : int -> bool = Numutil.string_bit b in
  let ith_response (i:int) (r:nat) : nat =
    bit_respond ~p'q' ~alpha r (ith_challenge i)
  in
  List.mapi ith_response rs

let log_checksum ~n (b:string) (h:nat) (g:nat) (ss:nat list) : nat list =
  let ith_challenge : int -> bool = Numutil.string_bit b in
  let ith_checksum (i:int) (s:nat) : nat =
    let b = ith_challenge i in
    bit_checksum ~n ~h ~g b s
  in
  List.mapi ith_checksum ss

(*
	k logs, all challenges.
*)

type proof = string * nat list list

let hash_inputs ~n ~g' ~hs ~vs : string =
  let hash = Parm.new_hash() in
  Hashutil.add_nat hash n;	(* modulus *)
  Hashutil.add_nat hash g';	(* generator *)
  Hashutil.add_nat_list hash hs;	(* k bases *)
  Hashutil.add_list (Hashutil.add_nat_list) hash vs;	(* k*hash_bit values *)
  hash#result

let prove ?rng ~n ~g' ~gs ~hs ~alphas ~p'q' =
  let k = List.length gs in
  if k != List.length hs
  || k != List.length alphas
  then invalid_arg "prove";
  (* k*hash_bits random values *)
  let rs : nat list list = Listutil.revgen (fun () -> log_rand ?rng ~p'q') k in
  (* k*hash_bits commitments *)
  let ts : nat list list = List.map2 (log_commit ~n) hs rs in
  (* hash_bits challenge bits *)
  let b : string = hash_inputs ~n ~g' ~hs ~vs:ts in
  (* k*hash_bits responses *)
  let ss : nat list list = List.map2 (log_respond ~p'q' b) alphas rs in
  (b,ss)

let check ~n ~g' ~gs ~hs (b,ss:proof) =
  let k = List.length gs in
  if k != List.length hs then invalid_arg "verify";
  if String.length b * 8 != hash_bits then error "wrong challenge count";
  if List.length ss != k then error "wrong response count";
  (* k*hash_bits checksums *)
  let vs : nat list list = Listutil.map3 (log_checksum ~n b) hs gs ss in
  (* hash over checksums *)
  let b' : string = hash_inputs ~n ~g' ~vs ~hs in
  if b != b' then error "wrong checksums"
