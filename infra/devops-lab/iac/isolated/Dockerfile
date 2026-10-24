FROM python@sha256:fbecd461fc72d21b2143c6eaba25143738079154a6d0ea3da3aec724f50eed4a
COPY terraform /usr/local/bin/terraform
COPY providers/ /opt/terraform/providers/
COPY source/ /opt/terraform/source/
COPY worker.py sandbox.py /opt/terraform/
COPY terraform.rc /opt/terraform/terraform.rc
RUN chmod 0555 /usr/local/bin/terraform && mkdir -p /work && chown 65532:65532 /work
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["python3", "-u", "/opt/terraform/worker.py"]
