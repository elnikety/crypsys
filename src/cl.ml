module Bn = Cryptokit.Bn
module Listutil = Util.Listutil
module Numutil = Util.Numutil
module Rsa = Util.Rsa

(** [mod_mult_power v g m n] returns [v g^m mod n]. *)
let mod_mult_power v g m n =
  Numutil.mod_mult v (Bn.mod_power g m n) n

(**
	[mod_mult_powers v [g₁; ...; g_k] [m₁; ...; m_k] n] returns
		[v g₁^{m₁} ⋯ g_k^{m_k} mod n].
	It raises an exception if the lists have different lengths.

	It returns a copy of v if the lists are empty.
*)
let mod_mult_powers v gs ms n =
  List.fold_left2 (mod_mult_power n) (Bn.copy v) gs ms

module Make(Parm: Clsig.PARM): Clsig.CL = struct

include Parm

let () =
  if rsa_modulus_bits land 1 > 0
  || prime_bits < message_bits+2
  then invalid_arg "Make"

let rsa_factor_bits = rsa_modulus_bits/2
let random_bits = rsa_modulus_bits+message_bits+reduction_bits

type key = { n: Nat.nat; p: Nat.nat; gs: Nat.nat list; c: Nat.nat }
type signat = { e: Nat.nat; s: Nat.nat; v: Nat.nat }

let new_key ?rng ?modulus () =
  let m = Rsa.new_special ?rng ?modulus rsa_modulus_bits in
  let (n,p,_) = Rsa.factors m in
  let g' = Rsa.new_QR_n_generator ?rng m in
  let new_base' = Rsa.new_QR_n_member ?rng ~base:g' m in
  let new_base () = let (_,g) = new_base' () in g in
  let gs = Listutil.revgen new_base (messages_per_block+1) in
  let c = new_base() in
  { n = n; p = p; gs = gs; c = c }

(** (∏_i a_i^{m_i}) b^s c mod n *)
let baseval key ms s = mod_mult_powers key.c key.gs (s::ms) key.n

let nats_of_block msgs =
  if List.length msgs != messages_per_block
  then invalid_arg "sign"
  else List.map (Numutil.nat_of_msg message_bits) msgs

let sign ?rng key msgs =
  let ms = nats_of_block msgs in
  let e = Bn.random_prime ?rng prime_bits in
  let s = Bn.random_nat ?rng random_bits in
  let v' = baseval key ms s in	(* (∏_i a_i^{m_i}) b^s c mod n *)
  let einv = Bn.mod_inv e key.n in	(* e⁻¹ mod n *)
  let v = Bn.mod_power v' einv key.n in	(* ((∏_i a_i^{m_i}) b^s c)^{1/e} mod n *)
  { e = e; s = s; v = v }

let verify key msgs signat =
  let ms = nats_of_block msgs in
  let {e; s; v} = signat in
  let v'1 = Bn.mod_power v e key.n in	(* v^e mod n *)
  let v'2 = baseval key ms s in	(* (∏_i a_i^{m_i}) b^s c mod n *)
  Bn.num_bits e = prime_bits
  && Bn.compare v'1 v'2 = 0

end

(* Values from the paper, section 2. *)
module Parm1024 = struct
  let messages_per_block = 1
  let rsa_modulus_bits = 1024
  let message_bits = 160
  let reduction_bits = 160
  let prime_bits = message_bits+2
end

module CL = Make(Parm1024)
