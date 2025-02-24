1. Added Spark Java web framework dependency in pom.xml: (maven project configuration)

<pre> ```xml
    <dependency>
        <groupId>com.sparkjava</groupId>
        <artifactId>spark-core</artifactId>
        <version>2.9.4</version>
    </dependency>
```</pre>

(maven will download Spark during compilation)


2. Added a Web Server Class (WebDashboard.java):

This file initializes a Spark Web Server on port 4567

It'll give us a server for the honeypot dashboard at:
http://localhost:4567/index.html

3. our main file SSHHoneypot.java initializes both servers, the ssh server and the new Spark server.

4. Added src/main/resources/public/index.html
The html/javascript for the homepage.
