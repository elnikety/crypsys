type 'a pp = Format.formatter -> 'a -> unit

val pp_bytes: string pp
val pp_nat: Nat.nat pp

val pp_rogue_key: Rogue.key pp
val pp_group_pubkey: Group.pubkey pp
val pp_group_key: Group.key pp

type issuer = Group.key * Rogue.key
type issuer_pub = Group.pubkey * Rogue.key

val pp_issuer: issuer pp
val pp_issuer_pub: issuer_pub pp

val save_issuer: string -> issuer -> unit
val save_issuer_pub: string -> issuer_pub -> unit
