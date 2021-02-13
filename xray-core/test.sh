#!/bin/sh

xray version 2>&1 | grep "${2#*v}"