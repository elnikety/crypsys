module Bn = Cryptokit.Bn
module H = Hashtbl
module J = Json_type
module To = Json_type.Browse
type nat = Nat.nat

let bytes_of_hex (s:string) : string =
  let fromhex = Cryptokit.Hexa.decode () in
  Cryptokit.transform_string fromhex s

let to_bytes (j:J.t) : string = bytes_of_hex (To.string j)

let to_nat (j:J.t) : nat = Bn.nat_of_bytes (to_bytes j)
let to_nat_list_list : J.t -> nat list list = To.list (To.list to_nat)

type table = (string,J.t) Hashtbl.t

let to_table (j:J.t) : table = To.make_table (To.objekt j)

let get (p:J.t -> 'a) (table:table) (name:string)  : 'a =
  let json = Hashtbl.find table name in p json

let get_nat : table -> string -> nat = get to_nat

let to_rogue_key (j:J.t) : Rogue.key =
  let open Rogue in
  let h = to_table j in
  { biggamma = get_nat h "biggamma";
    rho = get_nat h "rho";
    gamma = get_nat h "gamma" }

let to_provelog_proof (j:J.t) : Provelog.proof =
  let h = to_table j in
  let c = get to_bytes h "c" in
  let rs = get to_nat_list_list h "rs" in
  (c,rs)

let to_group_pubkey (j:J.t) : Group.pubkey =
  let open Group in
  let h = to_table j in
  { n = get_nat h "n";
    g' = get_nat h "g'";
    g = get_nat h "g";	h = get_nat h "h";
    s = get_nat h "s";	z = get_nat h "z";
    r0 = get_nat h "r0";	r1 = get_nat h "r1";
    proof = get to_provelog_proof h "proof" }

let to_group_key (j:J.t) : Group.key =
  let open Group in
  let h = to_table j in
  { pub = get to_group_pubkey h "pub";
    p'q' = get_nat h "p'q'" }

let to_issuer (j:J.t) : Pp.issuer =
  let h = to_table j in
  let group = get to_group_key h "group" in
  let rogue = get to_rogue_key h "rogue" in
  (group,rogue)

let to_issuer_pub (j:J.t) : Pp.issuer_pub =
  let h = to_table j in
  let group = get to_group_pubkey h "group" in
  let rogue = get to_rogue_key h "rogue" in
  (group,rogue)

type 'a parser = string -> 'a

let load (parse:J.t -> 'a) (file:string) : 'a =
  let json = Json_io.load_json file in
  parse json

let load_issuer = load to_issuer
let load_issuer_pub = load to_issuer_pub
