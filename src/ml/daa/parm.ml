module Bn = Cryptokit.Bn
module Hashutil = Util.Hashutil
module Numutil = Util.Numutil

let rsa_modulus_bits = 2048	(* ℓ_n *)
let halfkey_bits = 104	(* ℓ_f *)
let prime_total_bits = 368	(* ℓ_e *)
let prime_random_bits = 120	(* ℓ'_e *)
let random_bits = 2536	(* ℓ_v *)
let distribution_bits = 80	(* ℓ_∅ *)
let hash_bits = 160	(* ℓ_H *)
let reduction_bits = 80	(* ℓ_r *)
let rogue_modulus_bits = 1632	(* ℓ_Γ *)
let rogue_security_bits = 208	(* ℓ_ρ *)
let rogue_hash_bits = rogue_modulus_bits+distribution_bits

let new_hash = Cryptokit.Hash.sha1	(* length ℓ_H *)
let new_rogue_hash () =	(* length ℓ_Γ+ℓ_∅ *)
  Hashutil.adjust Cryptokit.Hash.sha1 ~numbits:rogue_hash_bits

let () =
  assert (prime_total_bits > distribution_bits+hash_bits+
    (max (halfkey_bits+4) (prime_random_bits+2)));
  assert (random_bits > rsa_modulus_bits+distribution_bits+
    hash_bits+(max (halfkey_bits+reduction_bits+3) (distribution_bits+2)));
  assert(rogue_security_bits = 2*halfkey_bits);
  assert(Hashutil.hash_bits new_hash = hash_bits);
  assert(Hashutil.hash_bits new_rogue_hash = rogue_hash_bits)

module Storage = struct

let identity n = Bn.bytes_of_nat n
let daaseed () = "DAAseed"

let cnt = ref 0
let get_cnt () = !cnt
let inc_cnt () = cnt := !cnt + 1

end

(* Utilities *)

let join ~f0 ~f1 =
  let f'1 = Numutil.shift_left_nat f1 halfkey_bits in
  Bn.add f0 f'1
