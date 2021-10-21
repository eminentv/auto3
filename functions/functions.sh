#!/bin/bash
SIGMA=$HOME/sigma
SIGMACTOOL=${SIGMA}/tools/sigmac
RULES=$SIGMA/rules
CONFIGS=$HOME/update_custom/custom-configs
UPDATE_RULES=$HOME/update_custom/rules

# Cloud
# AWS
function aws_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-cloudtrail.yml -rI ${RULES}/cloud/aws -o ${UPDATE_RULES}/aws/all/aws_ -e yml
    RULE=AWS-All
    RULE_PATH=${UPDATE_RULES}/aws/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function aws_critical () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-cloudtrail.yml -f 'level=critical' -rI ${RULES}/cloud/aws -o ${UPDATE_RULES}/aws/critical/aws_critical_ -e yml
    RULE=AWS-Critical
    RULE_PATH=${UPDATE_RULES}/aws/critical
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function aws_high () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-cloudtrail.yml -f 'level=high' -rI ${RULES}/cloud/aws -o rules/aws/high/aws_high_ -e yml
    RULE=AWS-High
    RULE_PATH=${UPDATE_RULES}/AWS/high
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done

}

function aws_medium () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-cloudtrail.yml -f 'level=medium' -rI ${RULES}/cloud/aws -o rules/aws/medium/aws_medium_ -e yml
    RULE=AWS-Med
    RULE_PATH=${UPDATE_RULES}/AWS/medium
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function aws_low () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-cloudtrail.yml -f 'level=low' -rI ${RULES}/cloud/aws -o rules/aws/low/aws_low_ -e yml
    RULE=AWS-Low
    RULE_PATH=${UPDATE_RULES}/aws/low
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

# O365
function o365_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -rI ${RULES}/cloud/m365 -o ${UPDATE_RULES}/o365/all/o365_ -e yml
    RULE=O365-all
    RULE_PATH=${UPDATE_RULES}/o365/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function o365_critical () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -f 'level=critical' -rI ${RULES}/cloud/m365 -o rules/o365/high/o365_critical_ -e yml
    RULE=O365-Critical
    RULE_PATH=${UPDATE_RULES}/o365/critical
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function o365_high () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -f 'level=high' -rI ${RULES}/cloud/m365 -o rules/o365/high/o365_high_ -e yml
    RULE=O365-High
    RULE_PATH=${UPDATE_RULES}/o365/high
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function o365_medium () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -f 'level=medium' -rI ${RULES}/cloud/o365 -o rules/o365/medium/o365_medium_ -e yml
    RULE=O365-Med
    RULE_PATH=${UPDATE_RULES}/o365/medium
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function o365_low () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -f 'level=low' -rI ${RULES}/cloud/o365 -o rules/o365/low/o365_low_ -e yml
    RULE=O365-Low
    RULE_PATH=${UPDATE_RULES}/o365/low
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

# Linux
function linux_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-combined.yml -rI ${RULES}/linux -o ${UPDATE_RULES}/linux/all/linux_ -e yml
    RULE=AWS-All
    RULE_PATH=${UPDATE_RULES}/linux/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function linux_critical () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-combined.yml -f 'level=critical' -rI ${RULES}/linux -o rules/linux/critical/linux_critical_ -e yml
    RULE=Linux-Critical
    RULE_PATH=${UPDATE_RULES}/linux/critical
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function linux_high () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-combined.yml -f 'level=high' -rI ${RULES}/linux -o rules/linux/high/linux_high_ -e yml
    RULE=Linux-High
    RULE_PATH=${UPDATE_RULES}/linux/high
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function linux_medium () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-combined.yml -f 'level=medium' -rI ${RULES}/linux -o rules/linux/medium/linux_medium_ -e yml
    RULE=Linux-Med
    RULE_PATH=${UPDATE_RULES}/linux/medium
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function linux_low () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-combined.yml -f 'level=low' -rI ${RULES}/linux -o rules/linux/low/linux_low_ -e yml
    RULE=Linux-Low
    RULE_PATH=${UPDATE_RULES}/linux/low
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

# Windows
function windows_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/winlogbeat-modules-enabled.yml -rI ${RULES}/windows -o ${UPDATE_RULES}/windows/all/windows_ -e yml
    RULE=AWS-All
    RULE_PATH=${UPDATE_RULES}/linux/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function windows_critical () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/winlogbeat-modules-enabled.yml -f 'level=critical' -rI ${RULES}/cloud/windows -o rules/windows/critical/windows_critical_ -e yml
    RULE=Windows-Critical
    RULE_PATH=${UPDATE_RULES}/windows/critical
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function windows_high () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/winlogbeat-modules-enabled.yml -f 'level=high' -rI ${RULES}/windows -o rules/windows/high/windows_high_ -e yml
    RULE=Windows-High
    RULE_PATH=${UPDATE_RULES}/windows/high
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function windows_medium () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/winlogbeat-modules-enabled.yml -f 'level=medium' -rI ${RULES}/windows -o rules/windows/medium/windows_medium_ -e yml
    RULE=Windows-Med
    RULE_PATH=${UPDATE_RULES}/windows/medium
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

function windows_low () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/winlogbeat-modules-enabled.yml -f 'level=low' -rI ${RULES}/windows -o rules/windows/low/windows_low_ -e yml
    RULE=Windows-Low
    RULE_PATH=${UPDATE_RULES}/windows/low
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

# Network
function network_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -rI ${RULES}/network -o ${UPDATE_RULES}/network/all/network_ -e yml
    RULE=Network-All
    RULE_PATH=${UPDATE_RULES}/network/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}

# Proxy
function proxy_all () {
    ${SIGMACTOOL} -t elastalert -c ${CONFIGS}/ecs-filebeat-10.yml -rI ${RULES}/proxy -o ${UPDATE_RULES}/proxy/all/proxy_ -e yml
    RULE=Proxy-All
    RULE_PATH=${UPDATE_RULES}/proxy/all
    for file in ${RULE_PATH}/*;
      do 
        echo "import: "${RULE}".conf" >> $file
      done
}
