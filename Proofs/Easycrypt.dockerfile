FROM ocaml/opam:alpine-ocaml-4.14
USER root
RUN apk add --no-cache git pkgconfig graphviz gtk+3.0-dev libpng-dev freetype-dev \
    autoconf make gcc g++ perl
USER opam
RUN opam update
RUN opam pin -yn add easycrypt https://github.com/EasyCrypt/easycrypt.git#r2026.06
RUN opam install --deps-only easycrypt -y
RUN opam install alt-ergo.2.6.3 -y
RUN opam install easycrypt -y
RUN opam exec -- easycrypt why3config
WORKDIR /artifact
ENTRYPOINT ["opam", "exec", "--", "easycrypt"]