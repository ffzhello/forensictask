package cn.edu.jslab6.autoresponse.forensictask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Created by zrwang on 2017/3/5.
 */
public class SystemConfig {
    private static final Logger LOG = LoggerFactory.getLogger(SystemConfig.class);

    // 案件接收http server 相关配置
    private String serverIP = "127.0.0.1";
    private int serverPort = 8888;

    private String resultSendUrl= "http://211.65.193.129/MONSTER/RecvResponseResult.php";

    private String mysqlIP = "127.0.0.1";
    private int mysqlPort = 3306;
    private String mysqlDatabase = "monster_test";
    private String mysqlUsername = "root";
    private String mysqlPasswd = "0000";

    // mongodb 相关配置
    private String mongoIP = "127.0.0.1";
    private int mongoPort = 27017;
    private String mongoDatabase = "autoresponse";
    private String mongoUsername = "root";
    private String mongoPasswd = "0000";

    //用来选择pfring网卡驱动，对应数据库中siteconfig中的id, id为27时默认对应dna1网卡
    private int sensorSiteid = 27;

    public String getMysqlIP() {
        return mysqlIP;
    }

    public void setMysqlIP(String mysqlIP) {
        this.mysqlIP = mysqlIP;
    }

    public int getMysqlPort() {
        return mysqlPort;
    }

    public void setMysqlPort(int mysqlPort) {
        this.mysqlPort = mysqlPort;
    }

    public String getMysqlDatabase() {
        return mysqlDatabase;
    }

    public void setMysqlDatabase(String mysqlDatabase) {
        this.mysqlDatabase = mysqlDatabase;
    }

    public String getMysqlUsername() {
        return mysqlUsername;
    }

    public void setMysqlUsername(String mysqlUsername) {
        this.mysqlUsername = mysqlUsername;
    }

    public String getMysqlPasswd() {
        return mysqlPasswd;
    }

    public void setMysqlPasswd(String mysqlPasswd) {
        this.mysqlPasswd = mysqlPasswd;
    }

    public String getMongoIP() {
        return mongoIP;
    }

    public void setMongoIP(String mongoIP) {
        this.mongoIP = mongoIP;
    }

    public int getMongoPort() {
        return mongoPort;
    }

    public void setMongoPort(int mongoPort) {
        this.mongoPort = mongoPort;
    }

    public String getMongoDatabase() {
        return mongoDatabase;
    }

    public void setMongoDatabase(String mongoDatabase) {
        this.mongoDatabase = mongoDatabase;
    }

    public String getMongoUsername() {
        return mongoUsername;
    }

    public void setMongoUsername(String mongoUsername) {
        this.mongoUsername = mongoUsername;
    }

    public String getMongoPasswd() {
        return mongoPasswd;
    }

    public void setMongoPasswd(String mongoPasswd) {
        this.mongoPasswd = mongoPasswd;
    }

    public int getSensorSiteid() {
        return sensorSiteid;
    }

    public void setSensorSiteid(int sensorSiteid) {
        this.sensorSiteid = sensorSiteid;
    }
    public SystemConfig() {

    }

    public SystemConfig(String confFile) throws IOException {
        load(confFile);
    }

    public String getServerIP() {
        return serverIP;
    }

    public void setServerIP(String serverIP) {
        this.serverIP = serverIP;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public String getTaskSendUrl() {
        return resultSendUrl;
    }

    public void setTaskSendUrl(String taskRecvUrl) {
        this.resultSendUrl = taskRecvUrl;
    }

    public void load(String confFile) throws IOException {
        Properties pps = new Properties();
        pps.load(new FileInputStream(confFile));
        if (pps.getProperty("serverIP") != null) {
            serverIP = pps.getProperty("serverIP");
        }

        if (pps.getProperty("serverPort") != null) {
            serverPort = Integer.parseInt(pps.getProperty("serverPort"));
        }

        if (pps.getProperty("mysqlIP") != null) {
            mysqlIP = pps.getProperty("mysqlIP");
        }

        if (pps.getProperty("mysqlPort") != null) {
            mysqlPort = Integer.parseInt(pps.getProperty("mysqlPort"));
        }

        if (pps.getProperty("mysqlDatabase") != null) {
            mysqlDatabase = pps.getProperty("mysqlDatabase");
        }

        if (pps.getProperty("mysqlUsername") != null) {
            mysqlUsername = pps.getProperty("mysqlUsername");
        }

        if (pps.getProperty("mysqlPasswd") != null) {
            mysqlPasswd = pps.getProperty("mysqlPasswd");
        }

        if (pps.getProperty("mongoIP") != null) {
            mongoIP = pps.getProperty("mongoIP");
        }

        if (pps.getProperty("mongoPort") != null) {
            mongoPort = Integer.parseInt(pps.getProperty("mongoPort"));
        }

        if (pps.getProperty("mongoDatabase") != null) {
            mongoDatabase = pps.getProperty("mongoDatabase");
        }

        if (pps.getProperty("mongoUsername") != null) {
            mongoUsername = pps.getProperty("mongoUsername");
        }

        if (pps.getProperty("mongoPasswd") != null) {
            mongoPasswd = pps.getProperty("mongoPasswd");
        }

        if (pps.getProperty("sensorSiteid") != null) {
            sensorSiteid = Integer.parseInt(pps.getProperty("sensorSiteid"));
        }

        if (pps.getProperty("resultSendUrl") != null) {
            resultSendUrl = pps.getProperty("resultSendUrl");
        }

        //LOG.debug("serverIP = {}, serverPort = {}, resultSendUrl = {}", serverIP, serverPort, resultSendUrl);
    }
}
