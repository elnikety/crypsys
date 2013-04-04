let error = Util.error
module Bn = Cryptokit.Bn
module Listutil = Util.Listutil
module Numutil = Util.Numutil
module Rsa = Util.Rsa
type nat = Nat.nat

type pubkey =
  { n: Nat.nat; g': nat;
    g: nat; h:nat; s: nat; z: nat; r0: nat; r1: nat;
    proof: Provelog.proof }
type key = { pub: pubkey; p'q': Nat.nat }

let new_key ?rng () =
  let m = Rsa.new_special ?rng Parm.rsa_modulus_bits in
  let (n,p,_) = Rsa.factors m in
  let p'q' = Rsa.p'q' m in
  let g' = Rsa.new_QR_n_generator ?rng m in
  let new_base h = Rsa.new_QR_n_member ?rng ~base:h m in
  let (xg,g) = new_base g' and (xh,h) = new_base g' in
  let (xs,s) = new_base h and (xz,z) = new_base h in
  let (xr0,r0) = new_base s and (xr1,r1) = new_base s in
  let gs = [g; h; s; z; r0; r1] in
  let hs = [g'; g'; h; h; s; s] in
  let alphas = [xg; xh; xs; xz; xr0; xr1] in
  let proof = Provelog.prove ?rng ~n ~g' ~gs ~hs ~alphas ~p'q' in
  let pub = { n; g'; g; h; s; z; r0; r1; proof } in
  { pub; p'q' } 

let pubkey key = key.pub

let check_key { n; g'; g; h; s; z; r0; r1; proof } =
  if Bn.num_bits n != Parm.rsa_modulus_bits
  then error "n out of bounds";
  
  (* PDS: Do we know more about the lengths of these values? *)
  let check_len v =
    if Bn.compare v n >= 0
    then error "value out of bounds"
  in
  List.iter check_len [g'; g; h; s; z; r0; r1];
  
  let gs = [g; h; s; z; r0; r1] in
  let hs = [g'; g'; h; h; s; s] in
  Provelog.check ~n ~g' ~gs ~hs proof
