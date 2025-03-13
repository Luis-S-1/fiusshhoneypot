#!/usr/bin/env bash

# Optional compile step:
mvn clean package

# Run the honeypot:
mvn exec:java -Dexec.mainClass="com.FIU.sshhoneypot.SSHHoneypot"

