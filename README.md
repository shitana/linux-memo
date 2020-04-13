# Usefull Commands

## ENCODAGE

| \!   | \#   | $    | &    | '    | (    | )    | \*  | \+  | ,   | /   | :   | ;   | \=  | ?   | @   | \[  | \]  |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0.21 | 0.23 | 0.24 | 0.26 | 0.27 | 0.28 | 0.29 | %2A | %2B | %2C | %2F | %3A | %3B | %3D | %3F | 0.4 | %5B | %5D |

## Docker

``` bash
#Fix using docker only with sudo
sudo usermod -a -G docker $USER
  
# show IP adress
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' CONTAINER

# BASH 
docker exec -it consulapibatch_consul-monitor-horsprod_1 /bin/bash
```

## SSH

``` bash
## Tunnelling SSH
ssh -L 2080:10.0.3.148:8080 -L 2040:10.0.3.148:8440 master01.cassandra.prod.mapreduce.b0. -N
## ignore host key check
- ajout de l'option "-o StrictHostKeyChecking=no" à la command "scp", afin que la clef d'hôte du serveur cible soit automatiquement acceptée
```

## HDFS

  - <http://hebex-tickets.orangeportails.net/vue_ticket.php?ticket_id=106590&onglet=0>

<!-- end list -->

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

Mettre à jour le depot  en local
git submodule update --init --recursive 
```

## LiniWini

### CRON

``` bash
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

# Display interface and their IP Address:
for int in $(echo `/sbin/ifconfig | grep Link |grep -v Loopback | cut -f1 -d" "`); do
 echo -e "Interface: $int\t=>\t`/sbin/ifconfig $int | grep "inet addr" | cut -d":" -f2 | cut -d" " -f1`";
done

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
./test_port es001.prod.cpark.ccl.b0. 9200
2017-12-14 11:31:05: The port 9200 on host es001.prod.cpark.ccl.b0. is OPEN.

./test_port es001.prod.cpark.ccl.b0. 9201
2017-12-14 11:31:05: The port 9201 on host es001.prod.cpark.ccl.b0. is not reachable: /dev/tcp/es001.prod.cpark.ccl.b0./9201.
```

# CONSUL

``` bash
#Check container
docker  -H swarm.priv.rec.caas.s0.:2375 ps | awk '{print $NF}' | grep '/consul'

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
oozie jobs -oozie http://master001.cassandra.preprod.mapreduce.b0.:11000/oozie -localtime -filter -len 10000 status=RUNNING

# faire un kill
oozie job -oozie http://master001.cassandra.preprod.mapreduce.b0.:11000/oozie -kill <job--id>
# une boucle qui fait des delete pour pns mais exclue quelques jobs 

for jobID in $(oozie jobs -oozie http://master001.cassandra.preprod.mapreduce.b0.:11000/oozie -localtime -filter status=RUNNING | grep pns | egrep -v 'amily-place-stats-workflow|push-stats-workflow' | awk '{print $1}' ) 
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
`ssh -N -L 18080:127.0.0.1:8080 master001.cassandra.preprod.mapreduce.b0. -f`  
`#CTRL+A D (to detach from your screen)`

``` bash
PASSWORD="le password"
HOST=node00X.cassandra.preprod.mapreduce.b1.
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
HOST=node00X.cassandra.preprod.mapreduce
COMPONENT="le composant"
curl -u "admin:$PASSWORD" -H "X-Requested-By: ambari" -X PUT -d '{"HostRoles": {"state": "INSTALLED"}}' \
"http://127.0.0.1:18080/api/v1/clusters/cassandra_preprod/hosts/$HOST/host_components/$COMPONENT"
```

### Start component

``` bash
PASSWORD="le password"
HOST=node00X.cassandra.preprod.mapreduce
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

``` bash
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
