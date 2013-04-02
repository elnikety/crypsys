let modulus_bits = Parm.rogue_modulus_bits
let security_bits = Parm.rogue_security_bits
module Bn = Cryptokit.Bn
module Hashutil = Util.Hashutil
module Numutil = Util.Numutil
let error = Util.error

type key = { biggamma: Nat.nat; rho: Nat.nat; gamma: Nat.nat }

(**
	If (r,m) = recover_r ~Γ ~ρ (),
	then rρ + m = Γ - 1.
	Specifically, if Γ and ρ come from a well-formed
	key, then m = 0.
*)	
let recover_r ~biggamma ~rho () : Nat.nat * Nat.nat =
  let biggamma' = Bn.sub biggamma Bn.one in
  Bn.quo_mod biggamma' rho

(**
	See setup step 5 in the DAA paper and Algorithm 4.84 in the
	Menezes et al.
*)

(** Pick a prime ρ of length ℓ_ρ. *)
let pick_rho ?rng () =
  Bn.random_prime ?rng security_bits

(** Pick r ∈ ℕ such that ρ ∤ r. *)
let rec pick_r ?rng ~rho =
  let rbits = modulus_bits - security_bits in
  let r = Bn.random_nat ?rng rbits in
  if Numutil.divides rho r
  then pick_r ?rng ~rho
  else r

(**
	Pick r ∈ ℕ and a prime Γ of length ℓ_Γ such that
		ρ ∤ r ∧ Γ = rρ + 1.
*)
let rec pick_biggamma ?rng ~rho =
  let r = pick_r ?rng ~rho in
  let biggamma = Bn.add Bn.one (Bn.mult r rho) in
  if Bn.num_bits biggamma = modulus_bits
  && Bn.is_probably_prime biggamma
  then (r,biggamma)
  else pick_biggamma ?rng ~rho

(**
	Pick γ ∈ ℤ∗_Γ such that
		∃γ' ∈ ℤ∗_Γ.
		γ'^r ≢ 1 (mod Γ) ∧
		γ = γ'^r mod Γ.
*)
let pick_gamma ?rng ~r ~biggamma ~rho =
  let biggamma' = Bn.sub biggamma Bn.one in
  let pick' : unit -> Nat.nat = Numutil.random_nat_in ?rng Bn.one biggamma' in
  let rec loop () =
    let gamma' = pick' () in
    let gamma = Bn.mod_power gamma' r biggamma in
    if Bn.compare gamma Bn.one != 0
    then gamma
    else loop()
  in
  loop()

let new_key ?rng () =
  let rho = pick_rho ?rng () in
  let (r,biggamma) = pick_biggamma ?rng ~rho in
  let gamma = pick_gamma ?rng ~r ~biggamma ~rho in
  { biggamma; rho; gamma }

(*
	See verification steps 2–3 in the DAA paper.
*)
let check_key {biggamma; rho; gamma} =
  if Bn.num_bits biggamma != modulus_bits
  then error "Γ out of bounds";
  
  if Bn.num_bits rho != security_bits
  then error "ρ out of bounds";
  
  if not(Bn.is_probably_prime biggamma)
  then error "Γ composite";
  
  if not(Bn.is_probably_prime rho)
  then error "ρ composite";
  
  let (r,m) = recover_r ~biggamma ~rho () in
  if Bn.compare m Bn.zero != 0
  then error "ρ does not divide Γ - 1";
  
  if Numutil.divides rho r
  then error "ρ divides r";
  
  let v = Bn.mod_power gamma rho biggamma in
  if Bn.compare v Bn.one != 0
  then error "γ bad"

let hash_name (name:string) : Nat.nat =
  let hash = Parm.new_rogue_hash() in
  hash#add_byte 1;
  hash#add_string name;
  Bn.nat_of_bytes(hash#result)

(*
	See join steps 2–3 and signing step 1 in the DAA paper.
*)
let compute_base ?rng ?bsn {biggamma; rho; gamma} =
  match bsn with
  | None ->
    let rho' = Bn.sub rho Bn.one in
    let i = Numutil.random_nat_in ?rng Bn.one rho' () in
    Bn.mod_power gamma i biggamma
  | Some name ->
    let (r,_) = recover_r ~biggamma ~rho () in
    let h = hash_name name in
    Bn.mod_power h r biggamma

let check_base key ~zeta : unit =
  let v = Bn.mod_power zeta key.rho key.biggamma in
  if Bn.compare v Bn.one != 0
  then error "ζ unusable"

let base ?rng ?bsn key =
  let zeta = compute_base ?rng ?bsn key in
  check_base key ~zeta; zeta

let tag key ~zeta ~f =
  if Bn.num_bits f >= security_bits then
  invalid_arg "tag";
  Bn.mod_power zeta f key.biggamma

let check_tag key n = ()
