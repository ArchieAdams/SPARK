# Artefact Evaluation Appendix

This is the artefact evaluation appendix for SPARK. 

## A.1 Badge claims

We claim two badges: **Artefacts Available** and **Artefacts Functional**.

- **Available**: archived on Zenodo, DOI [10.5281/zenodo.21207792](https://doi.org/10.5281/zenodo.21207792). The GitHub repository is public and requires no login to clone or download.
- **Functional**: the formal verification results (Table 2 and Theorem 1 in the paper) and the PAM implementation's unit tests are reproducible through the artefact. See A.3.

The empirical latency results (Section 5.3) require an android device in order to replicate and so does the app as it requires (Bluetooth, hardware-backed biometric keystore) not present in the simulator and is excluded from this evaluation; see the README's App section. `evaluation/` now documents the measurement methodology and provides the recorded data behind Fig. 4, for readers who want to attempt it on their own paired hardware; it remains outside this artefact's badge claims for the reason above.

We do not claim Reusable. `pam_authenticator.so` is a standard PAM module and could be wired into any PAM-aware service (`sudo`, `sshd`, a display manager) beyond the OS-login case in the paper, with no new code. We omit the claim because demonstrating it needs a paired Android device and we can't guarantee reviewers will have compatible hardware to hand.

### Known limitation: EC refresh

The app/PAM implementation now relies on the verifier nonce and ephemeral X25519 exchange for freshness. The proof model is unchanged for now and can be updated separately.

### Functional outcomes

- **F1**: SPARK-Pairing establishes agreement on the exchanged keys (Table 2, row 1: `e_UVer ⟹ e_VGen ∧ e_AGen`). Verified by `Proofs/spark-setup.pv`.
- **F2**: the authentication challenge stays secret (Table 2, row 2). Verified by `Proofs/spark-remote.pv` (`secret N` results).
- **F3**: unlock authenticates the paired device exactly once, injective agreement (Table 2, row 3: `e_VSuc ⟹inj e_AFin`). Verified by `Proofs/spark-remote.pv`.
- **F4**: the authenticator replies only to genuine challenges (Table 2, row 4: `e_AFin ⟹ e_VSta`). Verified by `Proofs/spark-remote.pv`.
- **F5**: the dual injective-agreement query is benign-false (Table 2, lone ○). A replayed challenge makes the authenticator re-sign, but the verifier rejects the stale response, so no double-unlock occurs. Verified by `Proofs/spark-remote.pv` (last `RESULT ... is false` line).
- **F6**: the hash commitment used in SPARK-Pairing is correct, binding, and hiding (Theorem 1). Verified by `Proofs/HashCommit.ec`.
- **F7**: the PAM implementation (frame codec, communication) matches its the specification. Verified by the `ctest` suite in `PAM/tests`.

## A.2 Quick start

Directory overview:

- `quickstart.sh`: runs the Proofs and PAM components end-to-end for a sanity check.
- `Proofs`: ProVerif and EasyCrypt models, Docker scripts. Backs F1-F6.
- `PAM`: verifier daemon and PAM module (C, cmake). Backs F7. `quickstart.sh` builds and tests it via `PAM/PAM.dockerfile`.
- `App`: companion Android app. Out of scope for this evaluation, see A.1.

Run:

```bash
./quickstart.sh
```

This builds and runs the Proofs (via Docker, `Proofs/run-proofs.sh`) and builds PAM and runs its unit tests (via Docker, `PAM/PAM.dockerfile`). It prints `Quick start: PASS` if everything succeeds. Requires only Docker, no local cmake/make or library installs needed.

## A.3 Functional evaluation

1. Run `./quickstart.sh` from the repo root. Allow extra time on the first run: the ProVerif/EasyCrypt/PAM Docker images are built from scratch, and opam package installs in particular can take a while. Repeat runs are fast since Docker caches the images.
2. Check the ProVerif output for `spark-setup.pv`:
   ```
   RESULT event(userVerified(sasV,sasA)) ==> event(verifierGenerated(v,a,sasV)) && event(authenticatorGenerated(v,a,sasA)) is true.
   ```
   This confirms **F1**.
3. Check the ProVerif output for `spark-remote.pv`:
   ```
   RESULT Query secret N [real_or_random] encoded as equivalence is true.
   RESULT secret N is true.
   RESULT inj-event(verifierSuccess(p1,p2,n)) ==> inj-event(authenticatorFinished(p1,p2,n)) is true.
   RESULT event(authenticatorFinished(p1,p2,n)) ==> event(verifierStarted(p1,p2,n)) is true.
   RESULT inj-event(authenticatorFinished(p1,p2,n)) ==> inj-event(verifierStarted(p1,p2,n)) is false.
   ```
   The first two `secret N` lines confirm **F2**. The third line confirms **F3**. The fourth confirms **F4**. The final `is false` line is expected and confirms **F5** (see the paper, Section 5.2, "benign" discussion).
4. Check the EasyCrypt output prints `Clean pass`. This confirms **F6**.
5. Check the `ctest` output: all PAM unit tests (frame codec, comms, crypto envelope) pass. This confirms **F7**.

Reviewers who want to exercise the PAM module interactively, rather than just its unit tests, can also use `pamtester` on a local, natively-built install per the README's PAM section. This requires a paired phone, so it's not part of the headless functional evaluation.

Evaluation time: roughly an hour on the first run, since the EasyCrypt image compiles its solver toolchain from source. A few minutes on repeat runs, once Docker has cached the images.
