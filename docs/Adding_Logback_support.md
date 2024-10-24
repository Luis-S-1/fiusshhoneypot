Adding Logback support to the project for incident logging:

Add logback dependency in our pom.xml file

    <!-- Logback dependencies -->
    <dependency>
        <groupId>org.slf4j</groupId>
        <artifactId>slf4j-api</artifactId>
        <version>2.0.9</version>
    </dependency>
    

    <dependency>
        <groupId>ch.qos.logback</groupId>
        <artifactId>logback-classic</artifactId>
        <version>1.4.11</version>
    </dependency>


create empty directory named resources in src/main/

Create a logback.xml file in the src/main/resources directory to configure how Logback logs messages
Here’s a basic configuration to log to a file called honeypot.log:

<configuration>

    <appender name="FILE" class="ch.qos.logback.core.FileAppender">
        <file>honeypot.log</file>
        <append>true</append>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} - %msg%n</pattern>
        </encoder>
    </appender>

    <root level="INFO">
        <appender-ref ref="FILE" />
    </root>
    
</configuration>

import the Logger and LoggerFactory classes to our java file:
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

Write a logging statement in the java file for every println statement.
Example:
       System.out.println("SSH Honeypot listening on port 2224...");

        logger.info("SSH Honeypot listening on port 2224...");








