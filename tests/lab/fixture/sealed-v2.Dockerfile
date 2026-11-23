# Disposable LAB-only activation layer, never a service/release image.
# The unmodified candidate image is first built from the exact reviewed SHA.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
# Deliberately change just the hardcoded activation guard in this derivative
# image. Fail closed if the reviewed source no longer has the expected guard.
RUN python -c 'import sysconfig; from pathlib import Path; p=Path(sysconfig.get_paths()["purelib"])/"app"/"config.py"; s=p.read_text(); marker="SEALED_RUNTIME_READY = False"; assert s.count(marker)==1, "unexpected sealed activation guard"; p.write_text(s.replace(marker,"SEALED_RUNTIME_READY = True",1))'
LABEL org.sshmcp.lab-sealed-activation="synthetic-only"
USER 10001:10001
