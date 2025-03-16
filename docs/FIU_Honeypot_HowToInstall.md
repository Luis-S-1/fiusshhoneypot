How to install SSH honeypot:

We'll be using Apache MINA SSHD, a Java library that provides us with code for an SSH server.
See https://github.com/apache/mina-sshd

mina-sshd is more easily installed and compiled with the Maven build automation and project management tool.

So we'll set the honeypot as a maven project.

The current github repository contains the maven project, so:


on your test/secondary PC:

make sure you have java 17 sdk installed

Install Maven:
sudo apt-get install maven

then

create a folder to clone the repo into, cd into it, then do

git clone https://github.com/Luis-S-1/fiusshhoneypot.git

If it requests a username/password you can add a Token into Github.

then cd into FIUsshhoneypot

from there install the project with:

mvn clean install

then run the project with 

./run.sh
(This script will compile AND run the project)


On your client terminal (the 'primary' pc that tries to ssh into the honeypot) you may have to run
ssh-keygen -f "/home/yourusername/.ssh/known_hosts" -R "[ipaddr of honeypot]:2224"

every time the project is rebuilt, if you get an error message like
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @

when you try to ssh again.



---------------------------------------------------------------------------
If you modify any file in the project, rebuild the project with

mvn clean package

then run again with

./run.sh



NOTES:
How I initially created the maven project that I uploaded to github:

I did:

Install Maven:
sudo apt-get install maven

Set up a Maven Project:
mkdir maven_sshhoneypot
cd maven_sshhoneypot

initialize a Maven project in this folder:

mvn archetype:generate -DgroupId=com.FIU.sshhoneypot -DartifactId=FIUsshhoneypot -DarchetypeArtifactId=maven-archetype-quickstart -DinteractiveMode=false

cd FIUsshhoneypot/

Edit the pom.xml file to tell Maven to download and include the MINA SSHD library (a dependency), and to use
your version of Java for project building.
(see pom.xml file)

then to download these dependencies do

mvn install

then do

mvn compile

and run the project with

mvn exec:java -Dexec.mainClass="com.FIU.sshhoneypot.SSHHoneypot"

your starting java file should be in a directory like this:
/home/yourusername/maven_sshhoneypot/FIUsshhoneypot/src/main/java/com/FIU/sshhoneypot/SSHHoneypot.java

