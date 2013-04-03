module Bn = Cryptokit.Bn
module Hashutil = Util.Hashutil
module Listutil = Util.Listutil
module Numutil = Util.Numutil
module P = Parm
type nat = Nat.nat

let error = Util.error

let power_of_two (k:int) : Nat.nat = Numutil.shift_left_nat Bn.one k

let hash_string (s:string) : string =
  let hash = P.new_hash() in
  Cryptokit.hash_string hash s

(** R₀^{f₀} R₁^{f₁} S^{v'} mod n *)
let blind ~group ~f0 ~f1 ~v' : nat =
  let open Group in let {r0; r1; s; n} = group in
  let bases = [r0; r1; s] in
  let powers = [f0; f1; v'] in
  Numutil.mod_mult_powers Bn.one bases powers ~n

module Join = struct

let ith_key_hash ~daaseed ~pk'hash ~cnt (i:int) : string =
  let hash = P.new_hash() in
  hash#add_string daaseed;
  hash#add_string pk'hash;
  hash#add_byte i;
  hash#result

let key_hash ~rho ~daaseed ~pk'hash ~cnt : string =
  let i = (P.rogue_security_bits+P.distribution_bits)/P.hash_bits in
  let hs = Listutil.geni (ith_key_hash ~daaseed ~pk'hash ~cnt) i in
  let hash = P.new_hash() in
  Hashutil.add_list Hashutil.add_string hash hs;
  hash#result

let key ~rogue ~pk' : nat * nat =
  let rho = rogue.Rogue.rho in
  let daaseed = P.Storage.daaseed() in
  let pk'hash = hash_string pk' in
  let cnt = P.Storage.get_cnt() in
  let h = key_hash ~rho ~daaseed ~pk'hash ~cnt in
  let f = Bn.mod_ (Bn.nat_of_bytes h) rho in
  let f0 = Numutil.extract_nat f 0 P.halfkey_bits in
  let f1 = Numutil.extract_nat f P.halfkey_bits P.halfkey_bits in
  (f0,f1)

let blinding_factor_bits =
  P.rsa_modulus_bits+P.distribution_bits

type t =
  { group: Group.pubkey; rogue: Rogue.key;
    f0: nat; f1: nat; zeta_I: nat; n_I: nat; v': nat; u: nat }
    
let join ?rng ~group ~rogue ~pk' ~bsn =
  let (f0,f1) = key ~rogue ~pk' in
  let zeta_I = Rogue.base ?rng ~bsn rogue in
  let n_I = Rogue.tag rogue ~zeta:zeta_I ~f0 ~f1 in
  let v' = Bn.random_nat blinding_factor_bits in
  let u = blind ~group ~f0 ~f1 ~v' in
  let state = { group; rogue; f0; f1; zeta_I; n_I; v'; u } in
  (state,u,n_I)

end

module Joinreply = struct

type t =
  { group: Group.key; rogue: Rogue.key; bigu: nat; bign_I: nat;
    zeta_I: nat;  n_i: nat }

let reply ?rng ~group ~rogue ~bsn ~bigu ~bign_I =
  (* We don't implement rogue detection. *)
  let zeta_I = Rogue.base ?rng ~bsn rogue in
  let n_i = Bn.random_nat ?rng P.hash_bits in
  let state = { group; rogue; bigu; bign_I; zeta_I; n_i } in
  (state,n_i)

end

(** See Step 6 in the DAA paper. *)
module Provejoin = struct

type rand = { rf0: nat; rf1: nat; rv': nat }
let join_rand ?rng () =
  let pick bits = Bn.random_nat ?rng bits in
  let fbits = P.halfkey_bits+P.distribution_bits+P.hash_bits in
  let rf0 = pick fbits in
  let rf1 = pick fbits in
  let v'bits = P.rsa_modulus_bits+2*P.distribution_bits+P.hash_bits in
  let rv' = pick v'bits in
  { rf0; rf1; rv' }

type commit = { tu: nat; tn_I: nat }
let join_commit ~state rs =
  let open Join in let { group; rogue; zeta_I } = state in
  let { rf0; rf1; rv' } = rs in
  let tu = blind ~group ~f0:rf0 ~f1:rf1 ~v':rv' in
  let tn_I = Rogue.tag rogue ~zeta:zeta_I ~f0:rf0 ~f1:rf1 in
  { tu; tn_I }

type response = { sf0: nat; sf1: nat; sv': nat }
let join_respond ~state rs c =
  let open Join in let { f0; f1; v' } = state in
  let { rf0; rf1; rv' } = rs in
  let c = Bn.nat_of_bytes c in
  let mix r v = Bn.mult_add c v r in	(* cv+r *)
  let sf0 = mix rf0 f0 in
  let sf1 = mix rf1 f1 in
  let sv' = mix rv' v' in
  { sf0; sf1; sv' }

let join_checksum ~state ~c ~ss =
  let open Joinreply in
  let { group; rogue; bigu; bign_I; zeta_I } = state in
  let group = Group.pubkey group in
  let { sf0; sf1; sv' } = ss in
  let n = group.Group.n in
  let biggamma = rogue.Rogue.biggamma in
  let c = Bn.nat_of_bytes c in
  let cinv = Bn.mod_inv c n in	(* cinv ≡ c⁻¹ mod n *)
  let a = Bn.mod_power bigu cinv n in	(* U^{-c} mod n *)
  let b = blind ~group ~f0:sf0 ~f1:sf1 ~v':sv' in
    (* R₀^{sf₀} R₁^{sf₁} S^{sv'} mod n *)
  let biguhat = Numutil.mod_mult a b n in
  let a = Bn.mod_power bign_I cinv n in	(* N_I^{-c} mod n *)
  let b = Rogue.tag rogue ~zeta:zeta_I ~f0:sf0 ~f1:sf1 in
  let bign_Ihat = Numutil.mod_mult a b biggamma in
  (biguhat, bign_Ihat)

(*
	PDS: The value n_t and the double hashing and possibly a layer
	of distribution_bits probably exist since the TMP worked with
	an untrusted host. We do everything on the cryptocard, so we
	could simplify things.
*)
let join_hash_inputs ~group ~bign_I ~bigu ~n_i ~n_t vu vn_I : string =
  let open Group in let { n; r0; r1; s } = group in
  let hash = P.new_hash() in	(* host hash *)
  Hashutil.add_nat_list hash [n; r0; r1; s; bigu; bign_I; vu; vn_I; n_i];
  let c_h = hash#result in
  let hash = P.new_hash() in	(* card hash *)
  hash#add_string c_h; Hashutil.add_nat hash n_t;
  hash#result

type proof = string * nat * response

let prove ?rng ~state ~n_i =
  if Bn.num_bits n_i > P.hash_bits
  then error "n_i out of bounds";
  let rs = join_rand ?rng () in
  let ts = join_commit ~state rs in
  let n_t = Bn.random_nat P.distribution_bits in
  let open Join in let { group; n_I; u } = state in
  let c = join_hash_inputs ~group ~bign_I:n_I ~bigu:u ~n_i ~n_t ts.tu ts.tn_I in
  let ss = join_respond ~state rs c in
  let pf = (c,n_t,ss) in
  let n_h = Bn.random_nat P.distribution_bits in
  (pf,n_h)

let check ~state (c,n_t,ss) =
  if String.length c * 8 != P.hash_bits then error "bad challenge";
  let open Joinreply in let { n_i } = state in
  let (biguhat,bign_Ihat) = join_checksum ~state ~c ~ss in
  let { group; bign_I; bigu } = state in
  let group = Group.pubkey group in
  let c' = join_hash_inputs ~group ~bign_I ~bigu ~n_i ~n_t biguhat bign_Ihat in
  if c != c' then error "wrong checksums"

end

module Sign = struct

type proof = { c': string; s_e: Nat.nat }

(*
	We pick the prime e from the set

		{ 2^{ℓ_e-1}, …, 2^{ℓ_e-1} + 2^{ℓ'_e - 1} }.
	
	Thus, if e is such a prime, then it has [prime_total_bits]
	bits but only the low-order [prime_random_bits] are
	unpredictable.
*)
let min_prime = power_of_two (Parm.prime_total_bits - 1)
let max_prime = Bn.add min_prime (power_of_two (Parm.prime_random_bits - 1))

let vhatbits = Parm.random_bits - 1

let sign ?rng ~state =
  error "nyi"

let check ~state ~proof ~cert ~v'' =
  error "nyi"

end
