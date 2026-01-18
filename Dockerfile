FROM golang:trixie AS build

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o rikugan .

FROM scratch

COPY --from=build --chmod=755 /app/rikugan /bin/

CMD ["rikugan"]
