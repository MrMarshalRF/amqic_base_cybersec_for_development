# Supply an audited, statically linked Linux binary named app in this context.
# Build dependencies and compilers stay outside the runtime image.
FROM scratch
COPY --chown=65532:65532 --chmod=0555 app /app
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app"]
