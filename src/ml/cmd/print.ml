let pp_nat = Util.pp_nat
module Bn = Cryptokit.Bn
let eprint = Format.eprintf

let (group,rogue) = Parse.load_issuer_pub Name.issuer_pub
let () = eprint "read %s@." Name.issuer_pub

let n = let open Group in group.n
let () = eprint "%d-bit modulus\n" (Bn.num_bits n)

let () = eprint "modulus: %a@." pp_nat n
