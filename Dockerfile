# Generate base image using https://github.com/sandialabs/ghidra-galore/
FROM ghidra:11.3.1

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

# Define build arguments with defaults
ARG KAIJU_RELEASE_URL=https://github.com/CERTCC/kaiju/releases/download/250220/ghidra_11.3.1_PUBLIC_20250220_kaiju.zip

RUN apt-get -y update && apt-get -y install busybox

RUN wget ${KAIJU_RELEASE_URL} -O - | busybox unzip -x -d ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/ -

RUN chmod a+x ${GHIDRA_INSTALL_DIR}/Ghidra/Extensions/kaiju/kaijuRun

ENTRYPOINT ["/opt/ghidra/Ghidra/Extensions/kaiju/kaijuRun"]
