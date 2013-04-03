let nat_of_int = Nat.nat_of_int
module Bn = Cryptokit.Bn
module RSA = Cryptokit.RSA

exception Error of string

let error msg = raise (Error msg)

let apply (f:'a -> 'b) (x:'a) : unit -> 'b =
  try let r = f x in fun () -> r
  with e -> fun () -> raise e

let memoize (f:unit -> 'a) : unit -> 'a =
  let cell = ref f in
  let fixup () = let r = apply f () in (cell := r; r()) in
  cell := fixup;
  fun () -> !cell()

let unwind ~protect f x =
  let r = apply f x in
  protect x; r()

module Listutil = struct

let revgen (f: unit -> 'a) (n: int) : 'a list =
  if n < 0 then invalid_arg "revgen";
  let rec loop i acc = if i = 0 then acc else loop (i-1) (f() :: acc) in
  loop n []

let geni f n =
  if n < 0 then invalid_arg "geni";
  let rec loop i =
    if i = n then []
    else let x = f i in x :: loop (i+1)
  in
  loop 0

let rec map3 f xs ys zs =
  match (xs,ys,zs) with
  | ([],[],[]) -> []
  | (x::xs, y::ys, z::zs) -> let r = f x y z in r :: map3 f xs ys zs
  | _ -> invalid_arg "map3"

end

module Numutil = struct

let qmod (n:int) (i:int) : int * int = (n / i, n mod i)

(*
  NB unboxed ocaml ints are 31 or 63 bits long. Only use this for
  small values.
*)
let int_bit (n:int) (i:int) : bool = (n lsr i) land 1 != 0

let string_bit s : int -> bool =
  let nbits = 8 * String.length s in
  fun i ->
  let i = nbits - 1 - i in	(* big-endian *)
  let (pos, i) = qmod i 8 in
  let i = 7 - i in	(* big-endian *)
  let byte = Char.code (s.[pos]) in
  int_bit byte i

let nat_bit n : int -> bool = string_bit (Bn.bytes_of_nat n)

let divides a b = Bn.compare (Bn.mod_ b a) Bn.zero = 0

let mod_mult a b c = Bn.mod_ (Bn.mult a b) c

let mod_mult_power v g m ~n =
  mod_mult v (Bn.mod_power g m n) n

let mod_mult_powers v gs ms ~n =
  List.fold_left2 (mod_mult_power ~n) (Bn.copy v) gs ms

let shift_left_nat n shift =
  let open Big_int in
  let i = big_int_of_nat n in
  let i = shift_left_big_int i shift in
  nat_of_big_int i

let extract_nat n offset len =
  let open Big_int in
  let i = big_int_of_nat n in
  let i = extract_big_int i offset len in
  nat_of_big_int i

let random_nat_in' ?rng min max : unit -> Nat.nat =
  let cmp = Bn.compare min max in
  if cmp > 0 then invalid_arg "random_nat";
  if cmp = 0 then fun () -> Bn.copy min else
  let k = Bn.sub max min in
  let nbits = Bn.num_bits k in
  fun () ->
  let n' = Bn.random_nat ?rng nbits in
  Bn.add min (Bn.mod_ n' k)

let random_prime_in' ?rng ?kind min max : unit -> Nat.nat =
  let random_nat = random_nat_in' ?rng min max in
  let rec loop () =
    let p = random_nat() in
    if Bn.is_probably_prime ?kind p
    then p
    else loop()
  in
  loop

let random_nat_in ?rng min max = random_nat_in' ?rng min max ()

let random_prime_in ?rng ?kind min max =
  random_prime_in' ?rng ?kind min max ()

let nat_of_msg maxbits msg =
  let m = Bn.nat_of_bytes msg in
  if Bn.num_bits m > maxbits
  then invalid_arg "nat_of_msg";
  m

end

module Hashutil = struct

let add_byte h b = h#add_byte b

let add_string h s = h#add_string s

let add_list add h xs = List.iter (add h) xs

let add_nat ?numbits h n =
  let s = Bn.bytes_of_nat ?numbits n in
  h#add_string s

let add_nat_list ?numbits h ns = add_list (add_nat ?numbits) h ns

let hash_bytes hashgen =
  let h = hashgen() in
  h#hash_size

let hash_bits hashgen = 8 * (hash_bytes hashgen)

class adjust (hashgen:unit -> Cryptokit.hash) (numbytes:int) =
  let lh = hash_bytes hashgen in
  let n = ((numbytes + lh - 1) / lh) in
  let () = if n <= 0 || n > 256 then invalid_arg "adjust" in
  object(self)
    val slaves = Array.init n
      (fun i ->
       let h = hashgen() in
       h#add_byte i;
       h)

    method hash_size = numbytes

    method add_substring s off len =
      for i=0 to n-1 do
        slaves.(i)#add_substring s off len
      done

    method add_string s =
      self#add_substring s 0 (String.length s)

    method add_char c =
      self#add_string (String.make 1 c)

    method add_byte b =
      self#add_char (Char.unsafe_chr b)

    method result =
      let dst = String.create numbytes in
      let rec loop i off =
        if i = n then dst
        else
          let src = slaves.(i)#result in
          String.blit src 0 dst off lh;
          loop (i+1) (off+lh)
      in
      loop 0 0

    method wipe =
      for i=0 to n-1 do
        slaves.(i)#wipe
      done
  end

let adjust hashgen ~numbits =
  if numbits mod 8 != 0 then invalid_arg "adjust";
  let numbytes = numbits / 8 in
  new adjust hashgen numbytes

end

module Rsa = struct

  type modulus =
    { size: int;
      n: Nat.nat;
      p: Nat.nat; q: Nat.nat;
      p': Nat.nat;
      q': Nat.nat;
      p'q': Nat.nat }

let new_special ?rng ?modulus numbits =
  match modulus with
  | None ->
    let key = RSA.new_key ?rng ~kind:RSA.special numbits in
    let p = Bn.nat_of_bytes key.RSA.p in
    let q = Bn.nat_of_bytes key.RSA.q in
    let p' = Bn.sg_of_safe p in
    let q' = Bn.sg_of_safe q in
    { size = numbits;
      n = Bn.nat_of_bytes key.RSA.n;
      p = p;
      q = q;
      p' = p';
      q' = q';
      p'q' = Bn.mult p' q' }
  | Some m ->
    if m.size != numbits
    then invalid_arg "new_special";
    m

let size m = m.size
let factors m = (m.n, m.p, m.q)
let n m = m.n
let p m = m.p
let q m = m.q
let p' m = m.p'
let q' m = m.q'
let p'q' m = m.p'q'

(*
	See
		http://math.stackexchange.com/questions/167478/how-to-compute-a-generator-of-this-cyclic-quadratic-residue-group
*)

let wrongorder a p =
  let m = Bn.mod_ a p in
  let meq n = (Bn.compare m n = 0) in
  meq Bn.zero || meq Bn.one || meq (Bn.sub p Bn.one)
  
let new_QR_n_generator ?rng m =
  let rec find() =
    let a = Bn.random_nat ?rng m.size in
    if wrongorder a m.p || wrongorder a m.q
    then find()
    else a
  in
  let a = find() in
  Bn.mod_power a (nat_of_int 2) m.n

let new_QR_n_member' ?rng ~base m =
  let pick_exponent = Numutil.random_nat_in' ?rng Bn.one m.p'q' in
  fun () ->
  let r = pick_exponent() in
  let g = Bn.mod_power base r m.n in
  (r,g)

let new_QR_n_member ?rng ~base m = new_QR_n_member' ?rng ~base m ()

end
