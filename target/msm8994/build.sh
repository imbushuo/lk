#!/bin/bash
make msm8994
signlk -i=./build-msm8994/emmc_appsboot.mbn -o=./build-msm8994/emmc_appsboot_signed.mbn