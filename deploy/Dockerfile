# syntax=docker/dockerfile:1

# ---- build stage ----
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads. go.sum may be absent in early phases (no deps yet);
# the glob tolerates that because go.mod always matches.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relay ./cmd/relay
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/relayctl ./cmd/relayctl

# ---- runtime stage ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relay /relay
COPY --from=build /out/relayctl /relayctl
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/relay"]
