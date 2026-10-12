# Barzakh Development Container
#
# Provides reproducible build environment with EDK II, QEMU, and Python tools
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent

FROM ubuntu:22.04

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV EDK2_VERSION=edk2-stable202405

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    nasm \
    iasl \
    uuid-dev \
    python3 \
    python3-pip \
    python3-distutils \
    git \
    curl \
    wget \
    # QEMU and TPM
    qemu-system-x86 \
    qemu-utils \
    swtpm \
    swtpm-tools \
    tpm2-tools \
    ovmf \
    # Development tools
    vim \
    less \
    shellcheck \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-benchmark \
    hypothesis \
    black \
    bandit \
    pylint \
    mypy

# Setup EDK II
WORKDIR /workspace
RUN git clone --depth 1 --branch ${EDK2_VERSION} \
    https://github.com/tianocore/edk2.git && \
    cd edk2 && \
    git submodule update --init --recursive && \
    make -C BaseTools

# Set environment
ENV WORKSPACE=/workspace
ENV PACKAGES_PATH=/workspace/edk2
ENV EDK_TOOLS_PATH=/workspace/edk2/BaseTools

# Create working directory
WORKDIR /workspace/barzakh

# Default command
CMD ["/bin/bash"]


