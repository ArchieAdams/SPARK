>**Note**: This project is under active development until the 22nd of July. The README will be updated with a quick-start guide and instructions for running the formal verification proofs before this date.




 
<svg xmlns="http://www.w3.org/2000/svg" width="510" height="200" viewBox="0 0 510 200">
  <rect width="510" height="200" fill="none"/>
  <text x="20" y="30.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">███████╗██████╗  █████╗ ██████╗ ██╗  ██╗</text>
  <text x="20" y="55.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">██╔════╝██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝</text>
  <text x="20" y="80.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">███████╗██████╔╝███████║██████╔╝█████╔╝ </text>
  <text x="20" y="105.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">╚════██║██╔═══╝ ██╔══██║██╔══██╗██╔═██╗ </text>
  <text x="20" y="130.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">███████║██║     ██║  ██║██║  ██║██║  ██╗</text>
  <text x="20" y="155.00" font-family="'DejaVu Sans Mono', 'Courier New', monospace" font-size="20" fill="currentColor" xml:space="preserve">╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝</text>
  <text x="20" y="175.00" font-family="'Share Tech Mono', 'DejaVu Sans Mono', 'Courier New', monospace" font-size="13" letter-spacing="2.5px" fill="currentColor" xml:space="preserve">SECURE PASSWORDLESS AUTHENTICATION WITH</text>
  <text x="20" y="190.00" font-family="'Share Tech Mono', 'DejaVu Sans Mono', 'Courier New', monospace" font-size="13" letter-spacing="2.5px" fill="currentColor" xml:space="preserve">REVEAL-COMMITTED KNOWLEDGE</text>
</svg>

<hr>

## Overview

SPARK is a research prototype created as part of my University of York BSc Computer Science dissertation. 
It has since been further refined with the help of my supervisor and co-author Roberto Metere, and is now being prepared for submission to SEFM'26.

SPARK is comprised of a PAM module and a companion app, which implement a secure challenge-response using the sign-then-encrypt scheme.
The underlying protocol is formally verified using ProVerif and EasyCrypt.

<hr>

## Contents
This repository contains the source code for the SPARK PAM module and companion app, as well as the formal verification proofs.

### Proofs
The `Proofs` directory contains the formal verification proofs for the SPARK protocol, implemented using ProVerif and EasyCrypt.

The `Proofs` directory contains the following files:
- `spark-setup.pv`: ProVerif model of the SPARK setup phase.
- `spark-remote.pv`: ProVerif model of the SPARK authentication phase.
- `HashCommit.ec`: EasyCrypt model of the hash commitment scheme used in SPARK.

In order to run the proofs, you will need to have ProVerif and EasyCrypt installed **or** docker.

#### Run locally

1. Install ProVerif 2.05 and EasyCrypt (see the respective documentation for installation instructions).
2. Navigate to the `Proofs` directory.
3. Run the following command to execute the ProVerif proofs:
   ```bash
   proverif spark-setup.pv
   ```
   ```bash
   proverif spark-remote.pv
   ```
4. Run the following command to execute the EasyCrypt proofs:
   ```bash
   easycrypt HashCommit.ec
   ```

#### Docker
Alternatively, you can use Docker to run the proofs without installing ProVerif and EasyCrypt locally.
We have made some simple bash scripts to run the proofs in a Docker container. To use the Docker scripts, follow these steps:

1. Install Docker (see the [Docker documentation](https://docs.docker.com/get-docker/) for installation instructions).
2. Navigate to the `Proofs` directory.
3. Run the following command to execute all of the proofs in a Docker container:
    ```bash
    ./run-proofs.sh
    ```
   You can also run each proof individually with `./run-proverif-setup.sh`, `./run-proverif-remote.sh` and `./run-easycrypt.sh`.


#### Expected output

The ProVerif proofs print one `RESULT` line per security query. `spark-setup.pv` should end with:

```
RESULT event(userVerified(sasV,sasA)) ==> event(verifierGenerated(v,a,sasV)) && event(authenticatorGenerated(v,a,sasA)) is true.
```

and `spark-remote.pv` should print:

```
RESULT Query secret N [real_or_random] encoded as equivalence is true.
RESULT secret N is true.
RESULT inj-event(verifierSuccess(p1,p2,n)) ==> inj-event(authenticatorFinished(p1,p2,n)) is true.
RESULT event(authenticatorFinished(p1,p2,n)) ==> event(verifierStarted(p1,p2,n)) is true.
RESULT inj-event(authenticatorFinished(p1,p2,n)) ==> inj-event(verifierStarted(p1,p2,n)) is false.
```

The final `is false` is expected: it is the one deliberately non-injective query in the paper (a replayed challenge makes the authenticator re-sign, which the verifier then rejects), so it is a pass, not a failure.

The EasyCrypt proof succeeds if it exits without errors the `run-easycrypt.sh` script checks this for you and prints `Clean pass`.

### PAM
The `PAM` directory contains the verifier side of SPARK: a standalone authenticator daemon and a PAM module (`pam_authenticator.so`) that hooks it into Linux authentication.

To build it you will need `cmake`, `make` and the following libraries: OpenSSL, BlueZ, libwebsockets, libcjson and tss2-esys (for the TPM 2.0 monotonic counter). On Debian/Ubuntu:

```bash
sudo apt install cmake make libssl-dev libbluetooth-dev libwebsockets-dev libcjson-dev libtss2-dev
```

Then, from the `PAM` directory:

1. Run the build script:
   ```bash
   ./build_pam.sh
   ```
   This builds the authenticator and the PAM module, and creates a test PAM configuration in `pam_config/`. Add `--install` to install the module to `/usr/lib/security` (requires sudo).
2. Pair a phone with the machine:
   ```bash
   ./setup.sh <username>
   ```
   This starts the pairing flow: both devices display an emoji SAS string, and you confirm on the phone that they match.


The unit tests (frame codec, communications and crypto envelope) can be run with:

```bash
ctest --test-dir build
```

### App
The `App` directory contains the companion Android app, which holds the authenticator key in the hardware-backed keystore and asks for a biometric-verified tap before answering a login challenge.

It is a standard Gradle project (minimum SDK 24). To build it, either open `App` in Android Studio, or from the `App` directory run:

```bash
./gradlew assembleDebug
```

and install the resulting APK on a phone. Pairing with a desktop is done from within the app, as described in the PAM section above.

<hr>

## License

SPARK is released under the Apache 2.0 license see [LICENSE](LICENSE).

