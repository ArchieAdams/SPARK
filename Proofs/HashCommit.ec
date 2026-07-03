(*
 * A formal verification of the (almost) naive hash-based commitment
 *
 *     H(m, r),  r a uniform full-length random value
 *
 * We reach statistical/computational hiding under the assumption of
 * e-regularity of the hash function, i.e., the commitment H(m, .) is at most
 * e away from the message-independent law dcom, measured as the advantage of
 * any distingusiher that picks a message and then tries to tell a real
 * commitment H(m, r) from a fresh dcom sample.
 *
 * For perfect hiding, no hash-function typical assumptions are made here,
 * i.e., no ROM or pre-image resinstance. So the result is general to any
 * e-regular function.
 * If eps is negligible, the hiding advantage is negligible, hence the scheme
 * is (statistically, and a fortiori computationally) hiding.
 * Whether the bound is statistical or computational is exactly whether
 * e bounds all D or only efficient D.
 *
 * We reach binding from collision resistance -- no regularity required.
 *)
require import AllCore DBool Distr.
require (*--*) Commitment.

theory HashCommitTypes.
  type message.
  type openingkey.
  type commitment.
end HashCommitTypes.
export HashCommitTypes.

(* Instantiate the Commitment scheme with the above types *)
clone import Commitment as CM with
  type CommitmentProtocol.value      <- unit,
  type CommitmentProtocol.message    <- message,
  type CommitmentProtocol.commitment <- commitment,
  type CommitmentProtocol.openingkey <- openingkey.
export CommitmentProtocol.

(* Defining the hash function H, being e-regular. *)
op H : message -> openingkey -> commitment.

op dopeningkey : openingkey distr.
axiom dopeningkey_ll : is_lossless dopeningkey.

(* The commitment-value distribution; dcom is whatever law H(m, .) induces *)
op dcom : commitment distr.
axiom dcom_ll : is_lossless dcom.

(* eps-regularity *)
op eps : real.
axiom eps_ge0 : 0%r <= eps.

module type RegDistinguisher = {
  proc choose() : message
  proc distinguish(c : commitment) : bool
}.

module RegReal (D : RegDistinguisher) = {
  proc main() : bool = {
    var m : message; var r : openingkey; var c : commitment; var b : bool;
    m <@ D.choose();
    r <$ dopeningkey;
    c <- H m r;
    b <@ D.distinguish(c);
    return b;
  }
}.

module RegIdeal (D : RegDistinguisher) = {
  proc main() : bool = {
    var m : message; var c : commitment; var b : bool;
    m <@ D.choose();
    c <$ dcom;            (* message-independent commitment *)
    b <@ D.distinguish(c);
    return b;
  }
}.

(* H(m,.) is eps-indistinguishable from dcom *)
axiom H_eps_regular (D <: RegDistinguisher) &m :
  `| Pr[RegReal(D).main()  @ &m : res]
   - Pr[RegIdeal(D).main() @ &m : res] | <= eps.

module HashCommit : CommitmentScheme = {
  proc gen() : unit = { return tt; }

  proc commit(h : unit, m : message) : commitment * openingkey = {
    var r : openingkey;
    r <$ dopeningkey;
    return (H m r, r);
  }

  proc verify(h : unit, m : message, c : commitment, d : openingkey) : bool = {
    return (H m d = c);
  }
}.

module IdealScheme : CommitmentScheme = {
  proc gen() : unit = { return tt; }

  proc commit(h : unit, m : message) : commitment * openingkey = {
    var c : commitment;
    c <$ dcom; (* ignores the message entirely *)
    return (c, witness);
  }

  proc verify(h : unit, m : message, c : commitment, d : openingkey) : bool = {
    return true;
  }
}.

section HashCommitSecurity.

  (* Correctness *)
  lemma hashcommit_correctness :
    hoare [Correctness(HashCommit).main : true ==> res].
  proof. proc; inline *; auto. qed.

  (* Computational binding *)
  module type Collider = {
    proc find_collision() : (message * openingkey) * (message * openingkey)
  }.

  module CollisionExperiment (A : Collider) = {
    proc main() : bool = {
      var x, y : message * openingkey;
      (x, y) <@ A.find_collision();
      return H x.`1 x.`2 = H y.`1 y.`2 /\ x <> y;
    }
  }.

  module ColliderRedBinder (B : Binder) : Collider = {
    proc find_collision() : (message * openingkey) * (message * openingkey) = {
      var c : commitment; var m, m' : message; var d, d' : openingkey;
      (c, m, d, m', d') <@ B.bind();
      return ((m, d), (m', d'));
    }
  }.

  (* Computational binding - QED *)
  lemma hashcommit_computational_binding (B <: Binder) &m :
       Pr[BindingExperiment(HashCommit, B).main() @ &m : res]
    <= Pr[CollisionExperiment(ColliderRedBinder(B)).main() @ &m : res].
  proof.
    byequiv => //.
    proc.
    inline ColliderRedBinder(B).find_collision HashCommit.verify HashCommit.gen.
    wp.
    call (_: true).
    auto => /> h h23_1 h45_1 _.
    rewrite h23_1 h45_1 //.
  qed.

  (* Statistical/computational hiding *)
  (* Input independece of IdealScheme.commit output *)
  local equiv ideal_commit_const :
    IdealScheme.commit ~ IdealScheme.commit : true ==> ={res}.
  proof. proc; auto. qed.

  lemma ideal_commit_ll : islossless IdealScheme.commit.
  proof. proc; rnd; skip => /=; exact dcom_ll. qed.

  (* Ideal hiding game = 1/2. Proff done by bit-flip symmetry *)
  local lemma hiding_ideal_half (U <: Unhider) &m :
    islossless U.choose =>
    islossless U.guess  =>
    Pr[HidingExperiment(IdealScheme, U).main() @ &m : res] = 1%r / 2%r.
  proof.
    move=> Hc Hg.
    pose p := Pr[HidingExperiment(IdealScheme, U).main() @ &m : res].
    pose q := Pr[HidingExperiment(IdealScheme, U).main() @ &m : !res].
    have flip : p = q.
      rewrite /p /q; byequiv (_: ={glob U} ==> res{1} = !res{2}) => //.
      proc.
      inline IdealScheme.gen.
      call (_: true).
      call ideal_commit_const.
      rnd (fun b => !b).
      call (_: true).
      auto => /> b _ b' //.
      smt().
    have total : p + q = 1%r.
      rewrite /p /q Pr[mu_not].
      have -> : Pr[HidingExperiment(IdealScheme, U).main() @ &m : true] = 1%r.
        byphoare => //.
        proc.
        call Hg; call ideal_commit_ll; rnd; call Hc.
        inline IdealScheme.gen; auto.
        by move=> *; rewrite dbool_ll.
        algebra.
    have := total; rewrite flip => *.
    smt().
  qed.

  module RegRedUnhider (U : Unhider) : RegDistinguisher = {
    var bbit : bool

    proc choose() : message = {
      var m0, m1 : message;
      (m0, m1) <@ U.choose();
      bbit <$ {0,1};
      return (bbit ? m1 : m0);
    }

    proc distinguish(c : commitment) : bool = {
      var b' : bool;
      b' <@ U.guess(c);
      return (bbit = b');
    }
  }.

  (* Real distinguishing game = real hiding game. *)
  local lemma red_real (U <: Unhider{-RegRedUnhider}) &m :
      Pr[HidingExperiment(HashCommit, U).main() @ &m : res]
    = Pr[RegReal(RegRedUnhider(U)).main() @ &m : res].
  proof.
    byequiv (_: ={glob U} ==> ={res}) => //.
    proc.
    inline RegRedUnhider(U).choose RegRedUnhider(U).distinguish
           HashCommit.gen HashCommit.commit.
    wp; call (_: true); wp; rnd; wp; rnd; call (_: true); auto.
  qed.

  (* Ideal distinguishing game = ideal hiding game. *)
  local lemma red_ideal (U <: Unhider{-RegRedUnhider}) &m :
      Pr[RegIdeal(RegRedUnhider(U)).main() @ &m : res]
    = Pr[HidingExperiment(IdealScheme, U).main() @ &m : res].
  proof.
    byequiv (_: ={glob U} ==> ={res}) => //.
    proc.
    inline RegRedUnhider(U).choose RegRedUnhider(U).distinguish
           IdealScheme.gen IdealScheme.commit.
    wp; call (_: true); wp; rnd; wp; rnd; call (_: true); auto.
  qed.

  (* Statistical/computtional hiding - QED *)
  lemma hashcommit_eps_hiding (U <: Unhider{-RegRedUnhider}) &m :
      islossless U.choose =>
      islossless U.guess  =>
      `| Pr[HidingExperiment(HashCommit, U).main() @ &m : res] - 1%r / 2%r |
      <= eps.
  proof.
    move=> Hc Hg.
    rewrite (red_real U &m).
    have h12 : Pr[RegIdeal(RegRedUnhider(U)).main() @ &m : res] = 1%r / 2%r.
      by rewrite (red_ideal U &m) (hiding_ideal_half U &m Hc Hg).
    rewrite -h12.
    exact (H_eps_regular (RegRedUnhider(U)) &m).
  qed.

  (* We exemplify that eps = 0 models a regular function, providing perfect hiding *)
  lemma hashcommit_eps0_perfect_hiding (U <: Unhider{-RegRedUnhider}) &m :
      islossless U.choose =>
      islossless U.guess  =>
      eps = 0%r =>
      Pr[HidingExperiment(HashCommit, U).main() @ &m : res] = 1%r / 2%r.
  proof.
    move=> Hc Hg He.
    have := hashcommit_eps_hiding U &m Hc Hg.
    rewrite He => H0.
    smt().
  qed.

end section HashCommitSecurity.

print hashcommit_correctness.
print hashcommit_computational_binding.
print hashcommit_eps_hiding.
print hashcommit_eps0_perfect_hiding.
