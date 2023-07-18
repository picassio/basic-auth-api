#!/bin/bash
count=0
alive="no"

docker compose up -d db rabbitmq redis

while [ "$count" -lt 6 ]; do
    dbhealth=$(docker inspect --format "{{.State.Health.Status}}" "$(docker compose ps -q db)")
    rabbitmqhealth=$(docker inspect --format "{{.State.Health.Status}}" "$(docker compose ps -q rabbitmq)")
 
    if [ "$dbhealth" == "healthy" ] && [ "$rabbitmqhealth" == "healthy" ] ; then
        alive="yes"
        break
    fi
 
    echo "waiting for mysql: $dbhealth"
    echo "waiting for rabbitmq: $rabbitmqhealth"
    sleep 10
    count=$((count+1))
done
 
if [ "$alive" = "yes" ]; then
    docker compose up -d auth api consumer
    exit 0
else
    echo "Services did not start up in time"
    exit 1
fi
