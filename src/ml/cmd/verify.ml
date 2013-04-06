let () = Format.eprintf "Verifying issuer parameters.@."

let (group,rogue) = Parse.load_issuer_pub Name.issuer_pub

let () = begin
	Group.check_key group;
	Rogue.check_key rogue;
	Format.eprintf "All ok@."
end
