package cn.edu.jslab6.autoresponse.forensictask;

import com.alibaba.druid.pool.DruidDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;

public class DruidDataSourcePool {
    private static final Logger LOG = LoggerFactory.getLogger(DruidDataSourcePool.class);
    private static DruidDataSource druidDataSource = null;
    private static SystemConfig systemConfig = new SystemConfig();

    static {
        try {
            //读取配置文件
            systemConfig = new SystemConfig("./system.properties");
            LOG.info("read system.properties");

            //设置连接池
            String driver = "com.mysql.jdbc.Driver";
            String url = "jdbc:mysql://" + systemConfig.getMysqlIP() + ":" + systemConfig.getMysqlPort() + "/" + systemConfig.getMysqlDatabase();
            String username = systemConfig.getMysqlUsername();
            String password = systemConfig.getMysqlPasswd();

            druidDataSource = new DruidDataSource();
            druidDataSource.setDriverClassName(driver);
            druidDataSource.setUrl(url);
            druidDataSource.setUsername(username);
            druidDataSource.setPassword(password);
            druidDataSource.setInitialSize(10);
            druidDataSource.setMinIdle(10);
            druidDataSource.setMaxActive(128);

            druidDataSource.setPoolPreparedStatements(false);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 从连接池获取连接
     * @return
     */
    public static synchronized Connection getConnection() {
        Connection connection = null;
        try {
            connection = druidDataSource.getConnection();
        } catch (SQLException e) {
            LOG.debug("Get connection exception...");
        }
        return  connection;
    }
}
