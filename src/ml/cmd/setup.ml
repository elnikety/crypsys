let eprint = Format.eprintf

let () = eprint "This takes several minutes. Please be patient.@."

let group = Group.new_key()
let rogue = Rogue.new_key()

let () = Pp.save_issuer Name.issuer (group,rogue)
let () = Pp.save_issuer_pub Name.issuer_pub (Group.pubkey group, rogue)
