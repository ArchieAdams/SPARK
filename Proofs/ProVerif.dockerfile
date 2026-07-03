FROM ocaml/opam:alpine-ocaml-4.14
USER root
RUN apk add --no-cache git pkgconfig graphviz gtk+3.0-dev libpng-dev freetype-dev
USER opam
RUN opam update && \
    opam install proverif.2.05 -y
WORKDIR /artifact
ENTRYPOINT ["opam", "exec", "--", "proverif"]