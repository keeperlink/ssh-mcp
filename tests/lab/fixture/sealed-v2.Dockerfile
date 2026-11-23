# Disposable LAB-only activation layer, never a service/release image.
# The unmodified candidate image is first built from the exact reviewed SHA.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
# Assert the reviewed image natively supports the sealed runtime. This test
# layer never patches installed application code and cannot be published as a
# production/signed image.
RUN python -c 'import sysconfig; from pathlib import Path; p=Path(sysconfig.get_paths()["purelib"])/"app"/"config.py"; s=p.read_text(); assert s.count("SEALED_RUNTIME_READY = True")==1, "candidate image lacks reviewed sealed activation"'
LABEL org.sshmcp.lab-sealed-activation="synthetic-only"
USER 10001:10001
