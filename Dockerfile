# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS builder
WORKDIR /src/go
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/policyweb ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/policyweb-create-user ./cmd/create-user

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S policyweb \
    && adduser -S -G policyweb -h /var/lib/policyweb policyweb \
    && install -d -o policyweb -g policyweb /var/lib/policyweb/sessions /var/lib/policyweb/users /srv/policyweb
COPY --from=builder /out/policyweb /usr/local/bin/policyweb
COPY --from=builder /out/policyweb-create-user /usr/local/bin/policyweb-create-user
RUN test -x /usr/local/bin/policyweb -a -x /usr/local/bin/policyweb-create-user
COPY --chown=policyweb:policyweb app /srv/policyweb/app
COPY --chown=policyweb:policyweb htdocs/extjs4 /srv/policyweb/extjs4
COPY --chown=policyweb:policyweb htdocs/silk-icons /srv/policyweb/silk-icons
COPY --chown=policyweb:policyweb resources /srv/policyweb/resources
COPY --chown=policyweb:policyweb go/pkg/backend/mail-templates /srv/policyweb/templates/mail
COPY --chown=policyweb:policyweb go/pkg/backend/html-templates /srv/policyweb/templates/html
COPY --chown=policyweb:policyweb app.html index.html ldap-login.html passwd.html /srv/policyweb/
RUN test -f /srv/policyweb/app.html \
    -a -f /srv/policyweb/extjs4/ext-all.js \
    -a -f /srv/policyweb/app/Application.js
COPY --chown=policyweb:policyweb app app
COPY --chown=policyweb:policyweb htdocs htdocs
COPY --chown=policyweb:policyweb resources resources
COPY --chown=policyweb:policyweb go/pkg/backend/mail-templates /srv/policyweb/templates/mail
COPY --chown=policyweb:policyweb go/pkg/backend/html-templates /srv/policyweb/templates/html
COPY --chown=policyweb:policyweb app.html index.html ldap-login.html passwd.html /srv/policyweb/
RUN mv app htdocs resources /srv/policyweb/

USER policyweb
ENV LISTENADDRESS=0.0.0.0 \
    LISTENPORT=8080 \
    STATIC_DIR=/srv/policyweb \
    POLICYWEB_CONFIG=/etc/policyweb/policyweb.conf
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/backend/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/policyweb"]
