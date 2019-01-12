package cn.edu.jslab6.autoresponse.forensictask;

import com.mongodb.MongoClientURI;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * @description: MongoDb数据库管理
 * @author: ffzheng
 * @create: 2019-01-11 21:11:58
 **/
public class MongoDbManager {
    private static Logger LOG = LoggerFactory.getLogger(MongoDbManager.class);

    private static SystemConfig systemConfig = null;
    private static MongoClient mongoClient = null;

    static {
        // 读取配置文件
        readConfig();

        // 创建MongoDB客户端实例
        init();
    }

    /**
     *  读取配置文件
     */
    private static void readConfig() {
        try {
            systemConfig = new SystemConfig("./system.properties");
        } catch (IOException e) {
            LOG.debug("read properties fail...");
        }
    }

    /**
     * 初始化mongodb客户端实例
     */
    private static void init() {
        if (systemConfig == null)
            readConfig();

        String mongoIP = systemConfig.getMongoIP();
        int mongoPort = systemConfig.getMongoPort();
        String mongoDatabase = systemConfig.getMongoDatabase();
        String mongoUsername = systemConfig.getMongoUsername();
        String mongoPasswd = systemConfig.getMongoPasswd();

        // 通过认证获取MongoDB连接
        MongoClientURI mongoClientURI = new MongoClientURI("mongodb://" + mongoUsername + ":" + mongoPasswd + "@" + mongoIP + ":" + mongoPort + "/?authSource=" + mongoDatabase);
        mongoClient = new MongoClient(mongoClientURI);
    }

    /**
     * 获取数据库连接
     * @return
     */
    public static MongoDatabase getMongoDB() {
        if (systemConfig == null || mongoClient == null) {
            init();
        }

        // 获取数据库连接
        return mongoClient.getDatabase(systemConfig.getMongoDatabase());
    }
}
