#!/bin/bash
echo "Starting Sultry with HTTP OOB"
cd /media/im2/plus/lab4/sultry
go build -o bin/sultry
./bin/sultry -mode dual -config config.json
