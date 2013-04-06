type nat = Nat.nat
module Bn = Cryptokit.Bn
module J = Json_type

let hex_of_bytes (bytes:string) : string =
  let tohex = Cryptokit.Hexa.encode () in
  Cryptokit.transform_string tohex bytes

let json_bytes (bytes:string) : J.t =
  J.String (hex_of_bytes bytes)

let json_nat (n:nat) : J.t = json_bytes (Bn.bytes_of_nat n)
let json_nat_list_list: nat list list -> J.t = J.Build.list (J.Build.list json_nat)

let json_rogue_key (key:Rogue.key) : J.t =
  let open Rogue in let { biggamma; rho; gamma } = key in
  J.Object [ "biggamma", json_nat biggamma;
    "rho", json_nat rho;
    "gamma", json_nat gamma ]

let json_provelog_proof (proof:Provelog.proof) : J.t =
  let (c,rs) = proof in
  J.Object [ "c", json_bytes c;
    "rs", json_nat_list_list rs ]

let json_group_pubkey (group:Group.pubkey) : J.t =
  let open Group in let { n; g'; g; h; s; z; r0; r1; proof } = group in
  J.Object [ "n", json_nat n;
    "g'", json_nat g';
    "g", json_nat g;	"h", json_nat h;
    "s", json_nat s;	"z", json_nat z;
    "r0", json_nat r0;	"r1", json_nat r1;
    "proof", json_provelog_proof proof ]

let json_group_key (key:Group.key) : J.t =
  let open Group in let { pub; p'q' } = key in
  J.Object [ "pub", json_group_pubkey pub;
    "p'q'", json_nat p'q' ]

let json_issuer (group,rogue) : J.t =
  J.Object [ "group", json_group_key group;
    "rogue", json_rogue_key rogue ]

let json_issuer_pub (group,rogue) : J.t =
  J.Object [ "group", json_group_pubkey group;
    "rogue", json_rogue_key rogue ]

type 'a pp = Format.formatter -> 'a -> unit

let lift (json:'a -> J.t) (fmt:Format.formatter) (x:'a) : unit =
  Json_io.Pretty.print fmt (json x)

let pp_bytes = lift json_bytes
let pp_nat = lift json_nat

let pp_rogue_key = lift json_rogue_key
let pp_group_pubkey = lift json_group_pubkey
let pp_group_key = lift json_group_key

type issuer = Group.key * Rogue.key
type issuer_pub = Group.pubkey * Rogue.key

let pp_issuer = lift json_issuer
let pp_issuer_pub = lift json_issuer_pub

let save (json:'a -> J.t) (file:string) (x:'a) : unit =
  Json_io.save_json file (json x)

let save_issuer = save json_issuer
let save_issuer_pub = save json_issuer_pub
