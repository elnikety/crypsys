let error = Util.error
let power_of_two = Util.Numutil.power_of_two
module Bi = Big_int
module Bn = Cryptokit.Bn
module Hashutil = Util.Hashutil
module Listutil = Util.Listutil
module Numutil = Util.Numutil
module P = Parm
type nat = Nat.nat

let mod_mult (a:nat) (b:nat) ~(n:nat) : nat =
  Numutil.mod_mult a b n
  
let mod_power (base:nat) (power:nat) ~(n:nat) : nat =
  Bn.mod_power base power n
  
let mod_powers (pairs:(nat * nat) list) ~(n:nat) : nat =
  Numutil.mod_powers Bn.one pairs ~n
  
let mod_inv (a:nat) ~n : nat =
  Bn.mod_inv a n

let square_nat (n:nat) : nat = Bn.mult n n

(*
	Compute [a'] and [b'] satisfying
		[a^{-b} ≡ {a'}^{b'}	(mod n)].
*)
let elim_neg_power (a:nat) (b:nat) ~(n:nat) : nat * nat =
  (mod_inv a ~n, b)

type origin = Card | Verifier
type msg = { bsn: string option; m: string; b: origin; n_v: nat }

type responses =
  { sv: nat; sf0: nat; sf1: nat;
    se: nat; see: nat;
    sw: nat; sew: nat;
    sr: nat; ser: nat }

type signat =
  { zeta: nat; bigt1: nat; bigt2: nat; bign_V: nat; c: nat; n_t: nat;
    ss: responses }

(*
	Our proof has the form
		SPK{ (f₀,f₁,v,e,w,r,ew,ee,er):
			Z ≡ ±T₁^e R₀^{f₀} R₁^{f₁} S^v h^{-ew}	(mod n) ∧
			T₂ ≡ ±g^w h^e (g')^r	(mod n) ∧
			1 ≡ ±T₂^{-e} g^{ew} h^{ee} (g')^{er}	(mod n) ∧
			N_V ≡ ζ^{f₀+f₁2^{ℓ_f}}	(mod Γ) ∧
			f₀,f₁ ∈ {0,1}^{ℓ_(f+∅+H+2)} ∧
			(e - 2^{ℓ_e}) ∈ {0,1}^{ℓ'_e+ℓ_(∅+H+1)}(n_t||n_v||b||m).

	Read the first three lines as “T₁ and T₂ commit to a certificate”.
	Read the next as “N_V relates to the secrets occurring in that
	certificate”.
	
	The fist line implies
		Z ≡ (T₁ / h^{ew/e})^e R₀^{f₀} R₁^{f₁} S^v	(mod n).
	Therefore, the verifier can conclude there exists a certificate
		(T₁/h^{ew/e}, e, v)
	for (f₀,f₁,v).

	The next two lines establish e | we.
*)

let hash_public_inputs ~group ~rogue ~zeta ~bigt1 ~bigt2 ~bign_V : Cryptokit.hash =
  let open Group in let { n; g; g'; h; r0; r1; s; z } = group in
  let open Rogue in let { biggamma; rho; gamma } = rogue in
  let hash = P.new_hash() in
  Hashutil.add_nat_list hash
    [n; g; g'; h; r0; r1; s; z; gamma; biggamma; rho;
     zeta; bigt1; bigt2; bign_V];
  hash

let hash_host_inputs ~hash ~tilde_T1 ~tilde_T2 ~tilde_T'2 ~tilde_N_V ~n_v : string =
  Hashutil.add_nat_list hash [tilde_T1; tilde_T2; tilde_T'2; tilde_N_V; n_v];
  hash#result

let hash_tpm_inputs ~c_h ~n_t ~b ~m : nat =
  let inner : string =
    let hash = P.new_hash() in
    hash#add_string c_h;
    Hashutil.add_nat hash n_t;
    hash#result
  in
  let hash = P.new_hash() in
  hash#add_string inner;
  hash#add_byte (match b with Card -> 0 | Verifier -> 1);
  hash#add_string m;
  Bn.nat_of_bytes (hash#result)
  
let sign ?rng ~group ~rogue ~secret ~cert msg : signat =
  let { bsn; m; b; n_v } = msg in
  if Bn.num_bits n_v > P.hash_bits
  then error "n_v out of bounds";
  let open Group in let { n; g'; g; h; r0; r1; s } = group in
  let open Join in let { biga; e } = cert and { f0; f1; v } = secret in
  let pick (numbits:int) : nat = Bn.random_nat ?rng numbits in
  let pick2 (numbits:int) : nat * nat = (pick numbits, pick numbits) in
  (*
	Construct the signature.
  *)
  let w, r = pick2 (P.rsa_modulus_bits+P.distribution_bits) in
  let bigt1 = mod_mult biga (mod_power h w ~n) ~n in
    (* T₁ = Ah^w mod n *)
  let bigt2 = mod_powers [g,w; h,e; g',r] ~n in
    (* T₂ = g^w h^e (g')^r mod n *)
  let zeta = Rogue.base rogue ?rng ?bsn in
    (* ζ = ⋯ rogue base for bsn:string option; see rogue.mli ⋯ *)
  let bign_V = Rogue.tag rogue ~zeta ~f0 ~f1 in
    (* N_V := ⋯ rogue tag with base ζ, power f₁||f₀; see rogue.mli ⋯ *)
  (*
	Construct the proof.
  *)
  (* “tpm” commitments *)
  let rv = pick (P.random_bits+P.distribution_bits+P.hash_bits) in
  let rf0, rf1 = pick2 (P.halfkey_bits+P.distribution_bits+P.hash_bits) in
  let tilde_T1t = mod_powers [r0,rf0; r1,rf1; s,rv] ~n in
    (* \tilde{T_{1t}} = R₀^{r_{f₀}} R₁^{r_{f₁}} S^{r_v} mod n *)
  let tilde_rf = Bn.mod_ (P.join rf0 rf1) rogue.Rogue.rho in
    (* \tilde{r_f} = r_{f₀} + r_{f₁}2^{ℓ_f} mod ρ *)
  let tilde_N_V = mod_power zeta tilde_rf rogue.Rogue.biggamma in
    (* \tilde{N_V} = ζ^{\tilde{r_f}} mod Γ *)
  (* “host” commitments *)
  let re = pick (P.prime_random_bits+P.distribution_bits+P.hash_bits) in
  let ree = pick (2*P.prime_total_bits+P.distribution_bits+P.hash_bits+1) in
  let rw, rr = pick2 (P.rsa_modulus_bits+2*P.distribution_bits+P.hash_bits) in
  let rew, rer = pick2 (P.prime_total_bits+P.rsa_modulus_bits+2*P.distribution_bits+P.hash_bits+1) in
  let hinv = mod_inv h ~n in
  let tilde_T1 = mod_powers [tilde_T1t,Bn.one; bigt1,re; hinv,rew] ~n in
    (* \tilde{T₁} = \tilde{T_{1t}} T₁^{r_e} h^{-r_{ew}} mod n *)
  let tilde_T2 = mod_powers [g,rw; h,re; g',rr] ~n in
    (* \tilde{T₂} = g^{r_w} h^{r_e} (g')^{r_r} mod n *)
  let bigt2inv = mod_inv bigt2 ~n in
  let tilde_T'2 = mod_powers [bigt2inv,re; g,rew; h,ree; g',rer] ~n in
    (* \tilde{T'₂} = T₂^{-r_e} g^{r_{ew}} h^{r_{ee} g'^{r_{er}} mod n *)
  (* challenge *)
  let hash = hash_public_inputs ~group ~rogue ~zeta ~bigt1 ~bigt2 ~bign_V in
  let c_h = hash_host_inputs ~hash ~tilde_T1 ~tilde_T2 ~tilde_T'2 ~tilde_N_V ~n_v in
  let n_t = pick P.distribution_bits in
  let c = hash_tpm_inputs ~c_h ~n_t ~b ~m in
  (* responses. NB s_e may be negative. *)
  let rval (r:nat) (v:nat) : nat = Bn.add r (Bn.mult c v) in
  let sv = rval rv v and sf0 = rval rf0 f0 and sf1 = rval rf1 f1 in
    (* s_v = r_v + c·v and s_{f₀} = r_{f₀} + c·f₀ and s_{f₁} = r_{f₁} + c·f₁ *)
  let se = rval re (Bn.sub e (power_of_two (P.prime_total_bits - 1)))
  and see = rval ree (square_nat e) and sw = rval rw w in
    (* s_e = r_e + c·(e - 2^{ℓ_e - 1}) and s_{ee} = r_{ee} + c·e² and s_w = r_w + c·w *)
  let sew = rval rew (Bn.mult e w) and sr = rval rr r
  and ser = rval rer (Bn.mult e r) in
    (* s_{ew} = r_{ew}+c·w·e and s_r = r_r+c·r and s_{er} = r_{er}+c·e·r *)
  let ss = { sv; sf0; sf1; se; see; sw; sew; sr; ser } in
  let signat = { zeta; bigt1; bigt2; bign_V; c; n_t; ss } in
  signat

(**
	A common sub-expression for checksums:
		[s_e + c2^{ℓ_e - 1}].
*)
let cse_bigt signat : nat =
  let { c; ss={ se } } = signat in
  Bn.add se (Bn.mult c (power_of_two (P.prime_total_bits - 1)))

(* \hat{T₁} = Z^{-c} T₁^{s_e + c2^{ℓ_e-1}} R₀^{s_{f₀}} R₁^{s_{f₁}} S^{s_v} h^{-s_{ew}} mod n *)
let checksum_t1 group signat : nat =
  let open Group in let { z; r0; r1; s; h; n } = group in
  let { bigt1; c; ss={ sf0; sf1; sv; sew } } = signat in
  mod_powers ~n
    [elim_neg_power z c ~n;
     bigt1, cse_bigt signat;
     r0,sf0; r1,sf1; s,sv;
     elim_neg_power h sew ~n]

(* \hat{T₂} = T₂^{-c} g^{s_w} h^{s_e+c2^{ℓ_e-1}} (g')^{s_r} mod n *)
let checksum_t2 group signat : nat =
  let open Group in let { g; h; g'; n } = group in
  let { bigt2; c; ss={ sw; sr } } = signat in
  mod_powers ~n
    [elim_neg_power bigt2 c ~n;
     g,sw;
     h,cse_bigt signat;
     g',sr]

(* \hat{T'₂} = T₂^{-(s_e+c2^{ℓ_e-1})} g^{s_{ew}} h^{s_{ee}} (g')^{s_{er}} mod n *)
let checksum_t'2 group signat : nat =
  let open Group in let { g; h; g'; n } = group in
  let { bigt2; ss={ sew; see; ser } } = signat in
  mod_powers ~n
    [elim_neg_power bigt2 (cse_bigt signat) ~n;
     g,sew; h,see; g',ser]

(* \hat{N_V} = {N_V}^{-c} ζ^{s_{f₀}+s_{f₁}2^{ℓ_f}} mod Γ *)
let checksum_nv rogue signat : nat =
  let open Rogue in let { biggamma } = rogue in
  let { bign_V; zeta; c; ss={ sf0; sf1 } } = signat in
  mod_powers ~n:biggamma
    [elim_neg_power bign_V c ~n:biggamma;
     zeta, P.join sf0 sf1]

let verify ~group ~rogue ~msg signat : unit =
  let { bsn; m; b; n_v } = msg in
  let { c; zeta; bigt1; bigt2; bign_V; n_t; ss={ sf0; sf1; se } } = signat in
  let key_bits = P.halfkey_bits+P.distribution_bits+P.hash_bits+1 in
  let prime_bits = P.prime_random_bits+P.distribution_bits+P.hash_bits+1 in
  if Bn.num_bits sf0 > key_bits then error "s_{f₀} out of bounds";
  if Bn.num_bits sf1 > key_bits then error "s_{f₁} out of bounds";
  if Bn.num_bits se > prime_bits then error "s_e out of bounds";
  if not (Rogue.valid rogue bign_V) then error "N_V out of bounds";
  if not (Rogue.valid rogue zeta) then error "ζ out of bounds";
  match bsn with
  | None -> ()
  | Some name ->
    let zeta' = Rogue.base ~bsn:name rogue in
    if Bn.compare zeta zeta' != 0 then error "ζ does not match basename";
  (* We do not implement the rogue list check. *)
  let hat_t1 = checksum_t1 group signat in
  let hat_t2 = checksum_t2 group signat in
  let hat_t'2 = checksum_t'2 group signat in
  let hat_nv = checksum_nv rogue signat in
  let hash = hash_public_inputs ~group ~rogue ~zeta ~bigt1 ~bigt2 ~bign_V in
  let c_h = hash_host_inputs ~hash ~tilde_T1:hat_t1 ~tilde_T2:hat_t2
    ~tilde_T'2:hat_t'2 ~tilde_N_V:hat_nv ~n_v
  in
  let c' = hash_tpm_inputs ~c_h ~n_t ~b ~m in
  if c != c' then error "checksum mismatch"
