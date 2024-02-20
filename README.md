[[_TOC_]]

# XLR

```bash
# Restart and check XLR
service xl-release stop ; sleep 15 ; ps -auxf | grep -v grep | grep java || ( service xl-release start ; sleep 30 ; grep "$(date +"%Y-%m-%d %H:")"  /usr/local/appliMM/log/xl-release.log | grep 'You can now point your browser to http://xlrelease-dev.ddddddd.com/' && sudo /usr/local/appliDD/bin/plugin-manager-cli.sh)

```

# AWS

```bash
# AWS-SSO
aws-sso cache

# List content of a object
aws --profile 2112121121:mtggft_Role_Fed s3api list-objects --bucket BUKETa --prefix livraison --query 'Contents[].Key'

# list name , instance ID and IP of all instance that contains REGEX in name
KEY_WORD=slm ; 
aws --region eu-west-1 --profile 54545445:Ops_Role_Fed ec2 describe-instances --filters "Name=tag:Name,Values=*${KEY_WORD}*" "Name=instance-state-name,Values=running" --query "Reservations[*].Instances[*].{InstanceId:InstanceId, Name:Tags[?Key=='Name'].Value | [0], PrivateIpAddress:PrivateIpAddress}" | jq -r '.[][] | [.InstanceId, .Name, .PrivateIpAddress] | @tsv'

# Get SecurityGroup SG
aws ec2 describe-security-groups --query "SecurityGroups[*].[GroupId,GroupName]" --output text --profil shitana --region eu-west-3

# View SG detail 
aws ec2 describe-security-groups --group-names "ec2-sg" --profil shitana --region eu-west-3 | jq

```

## Search instance + open console
* [Search and connect to ec2 instance](scripts/search_instances_ec2_ip)
* Prerequiste:
```bash
# AWS-SSO
aws-sso cache
```

* Howto:
```bash
devops:~$ search_instances_ec2 
Missing required option: -k <key_word>
Usage: /usr/local/bin/search_instances_ec2 -k <key_word> [-e <environment>] [-c] [-i <IP_Address>]
Options:
  -i <IP_Address>: ip address
  -k <key_word>: Specify the keyword to search
  -e <environment>: Specify the environment (dev, prod, prep, pfi)
  -c: Display the 'aws ssm start-session' command for each INSTANCE_ID

```

* Example:
```bash
devops:~$ search_instances_ec2 -k slm -c
i-059c36dsdsds03e9     sldsdsdssdagent        100.196.18.220
i-0150324242d2d173     sldsdsdsdess        100.196.154.197
i-0e73434348940b     slm-ddsdsdss    100.196.158.219
aws ssm start-session --profile 54545445:Ops_Role_Fed  --target i-059c36128e1620903e9 #slRE20-awa-agent
aws ssm start-session --profile 54545445:Ops_Role_Fed  --target i-0150d2df6c2221d2d173 #slREh-process
aws ssm start-session --profile 54545445:Ops_Role_Fed  --target i-0e731087ba223478940b #slRERrocess
```

# Usefull Ribiti

## PROXMOX

```bash 
# Get VMs IP:
for vm in $(qm list  | grep runni | awk '{print $1}'); do echo "VM ID: $vm ; VM NAME: $(qm list | grep $vm | awk '{print $2}')";  qm guest cmd $vm network-get-interfaces | grep -E 'name|"ip-address"|hardware-address'; done

for id in $(qm list | grep runn | awk '{print $1}'); do echo "$(qm list | grep $id | awk '{print $2}') "; qm guest cmd $id network-get-interfaces | jq '.[]| .name, ."ip-addresses"[0]."ip-address"' ; done | grep -E 'shopt|ens' -A1 | grep -v lo
```

## ENCODAGE

| \!   | \#   | $    | &    | '    | (    | )    | \*  | \+  | ,   | /   | :   | ;   | \=  | ?   | @   | \[  | \]  |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.21 | 0.23 | 0.24 | 0.26 | 0.27 | 0.28 | 0.29 | %2A | %2B | %2C | %2F | %3A | %3B | %3D | %3F | 0.4 | %5B | %5D |

## Docker

``` bash
#Fix using docker only with sudo
sudo usermod -a -G docker $USER

# Check Open port inside docker container
sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' container_name_or_id) -n netstat
  
# show IP adress
docker -H MACHINE:2375 inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' CONTAINER

# BASH 
docker -H MACHINE:2375 exec -it consulapibatch_consul-monitor-horsprod_1 /bin/bash

# IP ADD
for c in $(docker ps | awk '{ print $NF}' | grep -v NAME); do echo "######### $c ###############"; docker inspect $c | grep -B2 IPv4Address; echo "###################" ; done
```

## SSH

``` bash
## Tunnelling SSH
ssh -L 2080:10.0.3.148:8080 -L 2040:10.0.3.148:8440 master01.cassandra.prod.mapreduce.b0. -N
## ignore host key check
- ajout de l'option "-o StrictHostKeyChecking=no" à la command "scp", afin que la clef d'hôte du serveur cible soit automatiquement acceptée
```



``` bash
## Nettoyage du HDFS
HADDOP_USER_NAME=hdfs hdfs dfs -du -h
HADDOP_USER_NAME=hdfs hdfs dfs -rm -r -f -skipTrash /spark-history/application_1514381331836_0026_2
HADDOP_USER_NAME=hdfs hdfs dfs -rm -r -f -skipTrash /spark-history/application_1514381331836_0026_1.inprogress
HADDOP_USER_NAME=hdfs hdfs dfs -ls /spark-history
```

## CFEngine

``` bash
# Verify path of xymonclient conf file: to be executed on the machine:
cfagent -qDCFnirvanapaths -DCFxymonclient

#SVN Check Out
svn co svn+ssh://svn02.prod.cfengine.s1./svnroot/master/cfsystem
```

## Ansible

``` bash
 # ansible playbook expl
 ansible-playbook -i inventory/preprod palybook.yml -l hostname -vv --check --tags "deploy_artifact" --extra-vars host_to_deploy=trusty
 # List machine
 ansible-playbook tests/test.yml --list-hosts -i tests/inventory
 # Ansible Check connection to host:
 ansible -i inventory/test/hosts -m ping all
 
 # update dict variable:
 ## DICT var:
manage_src_list__role:
  file1_ext: '.disable'
  file2_ext: ''
 
 ## TASK
 set_fact:
    manage_src_list__role: "{{ manage_src_list__role | combine ({'file1_ext': '', 'file2_ext': '.disable'}) }}"
```

## GIT

``` bash
# Merge master to current branch: 
 git rebase master

 # Git tag
 export version=VERSION
 git checkout master
 git pull 
 git tag -a $version -m "$version  Desc" 
 git push origin $version

 # Set new repo
 git remote -v
 git remote set-url origin URL
 # Repo conf :
 cat <depot>/.git/config

# Update Submodul
git submodule foreach git pull origin master

# Mettre à jour le depot  en local
git submodule update --init --recursive 

# Delete remote branch
for b in $(git branch --list -a | grep "KEY_WORD" | sed 's,remotes/origin/,,g' | sort | uniq); do
   git checkout $b && git push origin --delete $b && git checkout staging && git branch -D $b; 
done
```

## LiniWini

### Display interface and their IP Address:

```bash
for int in $(echo $(ifconfig | grep flag |grep -v Loopback | cut -f1 -d":")); do  echo -e "Interface: $int $(/sbin/ifconfig $int | grep "inet " | awk '{print $2}')"; done

for int in $(echo `/sbin/ifconfig | grep Link |grep -v Loopback | cut -f1 -d" "`); do
 echo -e "Interface: $int\t=>\t`/sbin/ifconfig $int | grep "inet addr" | cut -d":" -f2 | cut -d" " -f1`";
done

for h in $(cat hosts | grep node02.inf | awk {'print $2}'); do echo "$h";  ssh vmtest$i.node02.infraplus.net 'for int in $(echo $(ifconfig | grep flag |grep -v Loopback | cut -f1 -d":")); do  echo -e "Interface: $int $(/sbin/ifconfig $int | grep "inet " | awk "{print $2}")"; done' ; done
```

### process
```bash
# Check usage for process every X Seconde
pidstat -h -r -u -v -p PID,PID,PID,... X
while sleep 1; do ps --no-headers -o '%cpu,%mem' -p "PID"; done
top -b -n 1 -p PID
```

### CRON

```bash
m h dom mon dow user  command

*   any value
,   value list separator
-   range of values
/   step values
@yearly (non-standard)
@annually   (non-standard)
@monthly    (non-standard)
@weekly (non-standard)
@daily  (non-standard)
@hourly (non-standard)
@reboot (non-standard)
```

### Partition

``` bash
/boot (lanceur de démarrage et en-têtes du noyau)
/dev (périphériques et pilotes)
/home (fichiers personnels)
/opt (logiciels complémentaires)
/srv (services système)
/tmp (fichiers temporaires)
/usr (applications)
/usr/local (données accessibles à tout utilisateur)
/var (spools serveur et logs).
```

### SED

``` bash
# Delete word between [ ] 
sed 's/\[[^ ]*\]//g' /tmp/test

# eliminer espace debut de la ligne:
sed "s/^ *//g"

# Upper case to lower Case
echo UAC3RAS2 | sed 's/\(.*\)/\L\1/'

# Afficher ensemble du ligne de "X"  jusqu'à "Y"
sed -n "/<X>/,/<Y>/p" <FILENAME>

# Formatage WIKI
sed 's/^=/==/g' /tmp/test | sed 's/=$/==/g'

# supprimer retour chariot  (https://stackoverflow.com/questions/1251999/how-can-i-replace-a-newline-n-using-sed)
sed ':a;N;$!ba;s/\n/ /g' /tmp/test
    :a create a label 'a'
    N append the next line to the pattern space
    $! if not the last line, ba branch (go to) label 'a'
    s substitute, /\n/ regex for new line, / / by a space, /g global match (as many times as it can)

###############################
```

### some command

``` bash
# Random password
tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''

# CREATE protected zipfile
alias randompassword="tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo ''"
PASSWORD=$(randompassword) && zip --password=$PASSWORD list_inscrit.zip Boulot/{extractDataUser-202105202246.csv,resultat_select_etoile-202105202247.csv} && echo $PASSWORD


# QUIT TELNET SESSION
Ctrl + Alt Gr + ]
then type "quit"

#UPDATE Keyboard conf PFSENSE http://blogmotion.fr/internet/pfsense-clavier-azerty-16564
kbdcontrol -l /usr/share/syscons/keymaps/fr.iso.kbd

# Enable sudo without passwd
USER  ALL=NOPASSWD: ALL  #add in the end of file<font color="blue"></font>


# supprimer retour chariot 
while read line; do printf "%s" "$line "; done < /tmp/test

# Search LDAP
LDAPUID="apibatchconsul"; 
ldapsearch -H ldap://ldap.gtm./ -b "ou=FT,ou=people,dc=fti,dc=net" -LLL -x '(&(uid='$LDAPUID'))'

# Display groups of a user
USER=""
id $USER | awk -F'groups=' '{print $NF}' | sed 's/,/\n/g' | sed 's/^[0-9].*(//g; s/)//g'

commande1 | commande2  - #le résultat de la commande1 est utilisé par la commande2
commande1 & commande2  - #les commandes sont exécutées simultanément, commande1 s'exécutant en arrière-plan
commande1 && commande2 - #si la commande1 réussi la commande2 est executée
commande1 || commande2 - #la commande2 s'exécute seulement si la commande1 échoue
commande1; commande2   - #les commandes sont exécutées dans l'ordre

# Nettoyage cache
free -h && sync && echo 3 > /proc/sys/vm/drop_caches && free -h

# Nettoyage LSOF
lsof | head
COMMAND     PID   TID  USER   FD      TYPE   DEVICE  SIZE/OFF   NODE   NAME
gdb -p $PID
p close($FD)
##### EXPLE ######
lsof | grep deleted
java        21568      root   24w     REG    253,2   23000046   18     /PAT/TO/FILE (deleted)

-bash-4.1# gdb -p 21568
(gdb) p close(24)
      $1 = 0
(gdb) quit
      A debugging session is active.
      Inferior 1 [process 21568] will be detached.
Quit anyway? (y or n) y
      Detaching from program: /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-0.b15.el6_8.x86_64/jre/bin/java, process 21568
-bash-4.1# lsof | grep "(deleted)"
############

######## SUDO ########
# Echo in fil with sudo
sudo -E -- sh -c 'echo "package_name install" > /etc/file'

# Enable sudo without password 
vim /etc/sudoers
USER  ALL=NOPASSWD: ALL

################

# Afficher les disks
lsblk

# create file 1 M:
dd if=/dev/urandom of=/tmp/test_cft_`date +"%Y%m%d"` bs=1k count=1000

# unmount NFS dans FSTAB:
cat /etc/fstab | grep nfs | awk '{ print  "umount " $2 }' 


# Add Ip address
ip address add [ip]/[mask-digits] dev [nic]

# Add route:
route add -host|-net DEST gw GW dev DEVICE ==> directement
echo "IPADD/XX via GW dev DEVICE" >> /etc/sysconfig/network-scripts/route-DEVICE ==> prise en compte dans le demarage

# désactiver l'expiration du compte:
chage -I -1 -m 0 -M 99999 -E -1 USER

# Version du linux:
dmesg | head -1
cat /proc/version
cat /etc/issue
cat /etc/*-release
lsb_release -a
egrep '^[^#]*title' /boot/grub/menu.lst | grep -v 'memtest'

# Date:
$(date +"%Y%m%d_%Hh%M")

# Redirect error:
CMD >>/PATH/TO/LOG/FILE 2>&1

################ FIND ###############
# Find and execute:
find . -name "*.sh" -print -exec dos2unix {} \;

# Split file:
split -b 1024k filename filename.part_

# Afficher les groups  process:
ps x -o  "%p %r %c" | grep <FILTER>

# Kill Group process:
kill -TERM  - -<PPID>

# Vider un fichier:
truncate -s 0 FILE

# Chercher plusieurs mot Grep:
grep -E "Mem|Swap" <FILE>

# Vérifier s'il y a assez de memoire pour libérer le SWAP
### Freecache
free && sync && echo 3 > /proc/sys/vm/drop_caches && free
### Test Swap
free | awk '/Mem:/ { ramfree=$4 } /Swap/ { swapused2=$3*2 } END { if (ramfree > swapused2) print "Execute swapoff -a; swapon -a ou service zram-config restart pour les VMs"; else print "Not enough of free memory in RAM, FREERAM: " ramfree " SWAPUSED * 2: " swapused2 ;}'

# Libérer le SWAP:
swapoff -a; swapon -a 

# SWAP by process
for file in /proc/*/status ; do
 awk '/VmSwap|Name/{printf $2 " " $3}END{ print ""}' $file;
done | sort -k 2 -n -r | less

# Check Format with Regex (BASH_REMATCH is based on delimiter used in the regex)
string="16:16:55"
if [[ "$string" =~ ^([0-9][0-9]):([0-9][0-9]):([0-9][0-9])$ ]]; then
 printf 'Got %s, %s and %s\n' \
   "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
fi

# Test Curl POST
curl -H "Content-Type: application/json; charset=UTF-8" -X POST --data @data.json http://localhost:8080/reco

# Java home
readlink -f /usr/bin/java | sed "s:/bin/java::"

### Openssl ###
# Openssl Check CSR
openssl req -in meta4u.qualif.csr.pem -noout -text
# Selfsigned
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mysitename.key -out mysitename.crt
sudo openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out gitonyvago.infraplus.net.crt -keyout gitonyvago.infraplus.net.key -subj "/C=FR/ST=Antibes/L=Antibes/O=Infraplus Consulting/OU=IT/CN=gitonyvago.infraplus.net"

# Print from Nth to last row:
awk '{for(i=2;i<=NF;i++){printf "%s ", $i}; printf "\n"}'  

# Sort based on specific column sperateur ":" column "3"
sort -t ":" -k3 -o <OUTPUT_FILE>

# Display file1 section by section based on lines of file2
for line in $(cat /path/to/file2); do
 sed -n "/####### $line #######/,/#####################/p" /path/to/file2;
 read;
 clear;
done

# Put difference between file1 and file2 in file3
while read line; do
 grep "^$line$" /path/to/file1 > /dev/null || echo $line >> /path/to/file3 ;
done < /pzth/to/file2
```

### Package management

``` bash
# Fix apt GPG Not Found:
KEY="GPK_KEY_NOTFOUND"
curl "http://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$key" 2>/dev/null | sed -n "/BEGIN/,/END/p" > key_file
sudo apt-key add key_file
rm add key_file

# chercher à quel paquet appartient le fichier
dpkg -S /file/name/

# Display version:
apt-cache madison PACKAGE

# Remove + Purge
apt-get remove --purge PACKAGE

# reInstall a hold PACKAGE
apt-get install --reinstall PACKAGE

# Verify depends and reverse Depends from package list:
while read line; do
 echo "####### $line #######";
 apt-cache rdepends --installed $line;
 echo "****************";
 dpkg -p $line | egrep -v '^P|^Ins|^Mai|^Archi|^Ver|^Fil|^Siz|^MD|^Ori|^Home';
 echo "#####################";
done < list_package_file

# Unhold package
sudo -E -- sh -c 'echo "package_name install"|dpkg --set-selections'
OR
sudo apt-mark unhold package_name
```

### test TCP cnx (without telnet)

``` bash
echo "DATEHEURE=\$(date +%Y-%m-%d\ %H:%M:%S)
TSTPORT=\$((echo > /dev/tcp/\$1/\$2) 2>&1)

if [ \$? -eq 0 ]; then
 echo \"\$DATEHEURE: The port \$2 on host \$1 is OPEN.\"
 exit 0
else
 STATUS=\$(echo \${TSTPORT} | awk -F ': ' '{print \$5}')
 echo \"\$DATEHEURE: The port \$2 on host \$1 is not reachable: \${STATUS}.\"
 exit 1
fi" > test_port
chmod 755 test_port
```

Example: Use IP instead of hostname (some machines doesn't support DNS
resolving)

``` bash
./test_port MACHINE 9200
2017-12-14 11:31:05: The port 9200 on host MACHINE is OPEN.

./test_port MACHINE 9201
2017-12-14 11:31:05: The port 9201 on host MACHINE is not reachable: /dev/tcp/MACHINE/9201.
```

## Add Swap

``` bash
dd if=/dev/zero of=/var/lib/vz/swap_file bs=1024 count=16777216
chmod 600 /var/lib/vz/swap_file
mkswap /var/lib/vz/swap_file
swapon /var/lib/vz/swap_file
```

# Python
## Virtualenv
### installation 
``` bash
sudo apt-get update
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.9 python3-pip pip python3-venv python3-virtualenv python2 python2-pip-whl python2-setuptools-whl -y
```

### Use case : creation des virtualenv **Python 2**
* creation de virtual env 
```bash
mkdir ~/virtualenvs/
cd ~/virtualenvs/
virtualenv --python=python2 python2
```

* Utiliser le virtualenv python2
```bash
# Check pip / python version before activation of virtenv python2
ubuntu@ip-10-196-87-76:~/virtualenvs$ python --version
Command 'python' not found, 

ubuntu@ip-10-196-87-76:~$ pip --version
pip 22.0.2 from /usr/lib/python3/dist-packages/pip (python 3.10)

# Activate python2 venv
ubuntu@ip-10-196-87-76:~$ source ~/virtualenvs/python2/bin/activate
(python2) ubuntu@ip-10-196-87-76:~$ 

# Check pip version after activation of virtenv python2
(python2) ubuntu@ip-10-196-87-76:~/virtualenvs$ python --version
Python 2.7.18

(python2) ubuntu@ip-10-196-87-76:~$ pip --version
pip 20.3.4 from /home/ubuntu/virtualenvs/python2/lib/python2.7/site-packages/pip (python 2.7)
```

### Use case : creation des virtualenv **par version de Ansible**
```bash
ubuntu@ip-10-196-87-76:$ cd ~/virtualenvs/
ubuntu@ip-10-196-87-76:~/virtualenvs$ virtualenv ansible2.9

ubuntu@ip-10-196-87-76:~/virtualenvs$ source ~/virtualenvs/ansible2.9/bin/activate
(ansible2.9) ubuntu@ip-10-196-87-76:~/virtualenvs$ python3 -m pip install --upgrade pip
.....
.....
Successfully installed pip-23.0

(ansible2.9) ubuntu@ip-10-196-87-76:~/virtualenvs$ python3 -m pip install ansible==2.9
....
....
Successfully built ansible
Installing collected packages: PyYAML, pycparser, MarkupSafe, jinja2, cffi, cryptography, ansible
Successfully installed MarkupSafe-2.1.2 PyYAML-6.0 ansible-2.9.0 cffi-1.15.1 cryptography-39.0.1 jinja2-3.1.2 pycparser-2.21
```

# TERRAFORM
``` bash
# Get DNS from terraform show output json
terraform show --json | jq '.values.root_module.resources[] | .values.public_dns'
```

# ES
``` bash
#List index:
curl -s -XGET ES_NODE:9200/_cat/indices?format=json | jq '.'
curl -s -XGET "ES_NODE:9200/_cat/indices?v"

#List index sorted by SIZE
curl -s -XGET "ES_NODE:9200/_cat/indices?pretty&v&s=store.size"

#Delete index
curl -XDELETE $ES_NODE:9200/INDEX_NAME

#Delete alias
 curl -XPOST $ES_NODE:9200/_aliases -d '
{
    "actions" : [
        { "add" : { "index" : "cliper_date", "alias" : "cliper_alias" } }
    ]
}'

``` 

# CONSUL

``` bash
#Check container
docker  -H MACHINE:2375 ps | awk '{print $NF}' | grep '/consul'

# Manage VIP
## Show VIP
vhype 10.98.231.97:443 show

## Remove node from VIP
vhype 10.98.231.97:443 --container --site sophia --environment rec remove 172.22.16.87:8443
```

# HOC

## Sonde disk

``` bash
# Check Disk / on master:
sudo du -s $(ll / | egrep -v 'var|tmp|usr|^-r|^l' | awk '{print "/"$NF}' | tail -n +4) 2>/dev/null | sort -n
```

## OOZIE Usefull commands

``` bash
# se connecter au master qui va bien , en user pns
# obtenir la liste des jobs
oozie jobs -oozie http://MACHINE_OOZIE:11000/oozie -localtime -filter -len 10000 status=RUNNING

# faire un kill
oozie job -oozie http://MACHINE_OOZIE:11000/oozie -kill <job--id>
# une boucle qui fait des delete pour pns mais exclue quelques jobs 

for jobID in $(oozie jobs -oozie http://MACHINE_OOZIE:11000/oozie -localtime -filter status=RUNNING | grep pns | egrep -v 'amily-place-stats-workflow|push-stats-workflow' | awk '{print $1}' ) 
do 
  echo "kill $jobID"
  oozie job -oozie http://master001.cassandra.prod.mapreduce.b0.:11000/oozie -kill $jobID
done
```

## AMBARI Usefull commands

### Tunnel SSH MapReduce PrePROD

  - Create a tunneling SSH rule to have access to master ambari API
    (Exple
PrePROD):

`screen -S ssh_tunnel`  
`ssh -N -L 18080:127.0.0.1:8080 MACHINE_OOZIE -f`  
`#CTRL+A D (to detach from your screen)`

``` bash
PASSWORD="le password"
HOST=node00X.AMBARI_NODE
```

### List all components of a given host

From your VDI (Exple PrePROD):

  - hostname: node001.cassanra.preprod.mapreduce.b1.
  - Cluster:
cassandra\_preprod

<!-- end list -->

``` bash
curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X GET "http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST" 2>/dev/null | sed -n "/host_components/,/],/p" | grep component_name | awk -F'"' '{print $4}'
```

### Component's Status

`curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X GET "`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components?fields=HostRoles/state>`"`

### Stop component

``` bash
PASSWORD="le password"
HOST=node00X.AMBARI_NODE
COMPONENT="le composant"
curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X PUT -d '{"HostRoles": {"state": "INSTALLED"}}' \
"http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components/$COMPONENT"
```

### Start component

``` bash
PASSWORD="le password"
HOST=node00X.AMBARI_NODE
COMPONENT="le composant"
curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X PUT -d '{"HostRoles": {"state": "STARTED"}}' \
"http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components/$COMPONENT"
```

### Delete component

`#List component:`  
`curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X GET "`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST>`" 2>/dev/null | sed -n "/host_components/,/],/p" | grep component_name | awk -F'"' '{print $4}'`  
  
`#ONE COMPONENT`  
`COMPONENT="le composant"`  
`curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X DELETE \`  
`"`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components/$COMPONENT>`"`  
  
`#ALL COMPONETNS`  
`for comp in $(curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X GET "`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST>`" 2>/dev/null | sed -n "/host_components/,/],/p" | grep component_name | awk -F'"' '{print $4}');`  
` do`  
`   echo $comp;`  
`   curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X DELETE "`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components/$comp>`";`  
`done`

### Delete Node

`curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X DELETE "`<http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST>`"`


## compression des logs ambari

  - Machines concernées

`tous les machines ambari-server`

  - Solution temporaire: gzip les anciens (si volumineux) fichiers de
    log :

<!-- end list -->

``` bash

 # Determiner les dossiers volumineux 
for dir in $(du -s /var/opt/hosting/log/* | sort -n | tail -n 2 | awk '{ print $NF }'); do
  find $dir -type f ! -name "*gz" -name "*.log*" -mtime +10 -exec ls -lh {} \; ;
done

 # gzip les anciens fichiers de logs
for dir in $(du -s /var/opt/hosting/log/* | sort -n | tail -n 2 | awk '{ print $NF }'); do
  find $dir -type f ! -name "*gz" -name "*.log*" -mtime +10 -exec gzip -f {} \; ;
done
```

  - Solution : Update configuration log4j pour compresser les fichiers
    de log

# IPTABLES

```bash
iptables -D POSTROUTING 2 
iptables -D PREROUTING 2 
iptables -L -v -n --line-numbers 
iptables -L -v -t nat -n --line-numbers 
iptables-save > /etc/iptables/rules.v4 
iptables -t masquerade -D POSTROUTING 2 
iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 8080 -j DNAT --to 192.168.10.2:8080 
iptables -t nat -D POSTROUTING 2 
iptables -t nat -D PREROUTING 2 
```

# POSTGRES
## generate backup script
```bash
sudo su - postgres
> /opt/db/ops/script_backup.sh; for db in $(psql -l | grep ' postg^Cs '| grep _rec | awk '{print $1}'); do echo "pg_dump $db > /var/opt/log/pgsql/BACKUP/backup_${db}_\$(date +\"%Y%m%d\").bak" >> /opt/db/ops/script_backup.sh ; echo "gzip /var/opt/log/pgsql/BACKUP/backup_${db}_$(date +"%Y%m%d").bak " >> /opt/db/ops/script_backup.sh; done
```

## restore backup

```bash
dropdb $DB_NAME
createdb $DB_NAME
psql $d < backup_${DB_NAME}_$(date +"%Y%m%d").bak 
```
