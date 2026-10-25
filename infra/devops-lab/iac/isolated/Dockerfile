FROM python@sha256:4ff19c6091d2441843e881d2101b0507d26624eb1e6844e7ccf1b24df75c42ca
# The worker only needs the standard library; remove the unused package installer
# and its bundled vulnerable dependencies, including ensurepip's reinstall wheel.
RUN python3 -m pip uninstall --yes pip \
    && python3 -I -c "import importlib.util,pathlib,shutil,sysconfig; shutil.rmtree(pathlib.Path(sysconfig.get_path('stdlib'))/'ensurepip'); assert importlib.util.find_spec('pip') is None"
COPY --chmod=0555 terraform /usr/local/bin/terraform
COPY --chmod=0555 providers/ /opt/terraform/providers/
COPY source/ /opt/terraform/source/
COPY worker.py sandbox.py /opt/terraform/
COPY terraform.rc /opt/terraform/terraform.rc
RUN mkdir -p /work && chown 65532:65532 /work
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["python3", "-u", "/opt/terraform/worker.py"]
