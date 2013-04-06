type 'a parser = string -> 'a

val load_issuer : Pp.issuer parser
val load_issuer_pub : Pp.issuer_pub parser
