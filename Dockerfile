FROM scratch
EXPOSE 5556
COPY oidc-testclient /
ENTRYPOINT ["/oidc-testclient"]
