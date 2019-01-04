package cn.edu.jslab6.autoresponse.forensictask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import java.util.HashSet;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;

/**
 * 数据库采集任务管理
 * Created by ffzheng on 2017/7/19.
 */

public class ActiveTaskManager {
    private static final Logger LOG = LoggerFactory.getLogger(ActiveTask.class);

    private static String sql = null;

    /**
     *  将新采集任务存入数据库
      * @param task
     */
    public static void addActivetaskToDB(ResponseTask task) {
        if (task == null)
            return;
    }

    /**
     * 通过状态读取数据库中的采集任务
     * @param status
     * @return
     */
    public static List<ActiveTask> getTaskListfromDB(TaskStatus status) {

        List<ActiveTask> taskList = new ArrayList<ActiveTask>();
        if (status == null)
            return taskList;

        sql = "select * from activetask where status = " + status.getValue();
        Statement statement = null;
        ResultSet resultSet = null;
        Connection conn = null;
        try {
            //Connection conn = DBConnectionManager.getConnection(1);
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();
            resultSet = statement.executeQuery(sql);
            while(resultSet.next()) {
                ActiveTask activeTask = new ActiveTask();
                activeTask.setId(resultSet.getInt("id"));
                activeTask.setTicketId(resultSet.getInt("ticketid"));
                activeTask.setIpString(resultSet.getString("iplist"));
                activeTask.setActions(resultSet.getString("action"));
                activeTask.setPriority(resultSet.getInt("priority"));
                activeTask.setFlowDirection(resultSet.getInt("inoutflag"));
                activeTask.setSrcIP(resultSet.getInt("srcipflag"));
                activeTask.setSrcIPDstIP(resultSet.getInt("srcipdstip"));
                activeTask.setDstIP(resultSet.getInt("dstipflag"));
                activeTask.setSrcPort(resultSet.getInt("srcport"));
                activeTask.setSrcPortDstPort(resultSet.getInt("srcportdstport"));
                activeTask.setDstPort(resultSet.getInt("dstport"));
                activeTask.setProtocol(resultSet.getInt("protocol"));
                activeTask.setStartTime(resultSet.getLong("starttime"));
                activeTask.setEndTime(resultSet.getLong("endtime"));
                activeTask.setSensorpkts(resultSet.getLong("sensorpkts"));
                activeTask.setSensorBytes(resultSet.getLong("sensorbytes"));
                activeTask.setThresholdPkts(resultSet.getInt("thresholdpkts"));
                activeTask.setUsername(resultSet.getString("username"));
                activeTask.setFilesplit(resultSet.getInt("filesplit"));
                activeTask.setStatus(resultSet.getInt("status"));
                activeTask.setDirPath("/home/monster/AutoResponse/HydraSensor/data/hydra_sensor/" + activeTask.getId() + "/");
                taskList.add(activeTask);

                //更新任务状态
                if (activeTask.getStatus() == 0) {
                    updateActiveTaskStatusByTaskId(activeTask.getId(), TaskStatus.SENSORING, null);
                    LOG.debug("从数据库获得新采集任务[id：" + activeTask.getId() + "]");
                }
            }
        }catch(SQLException e) {
            e.printStackTrace();
        }finally {
            //close
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (resultSet != null) {
                try {
                    resultSet.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
        return taskList;
    }

    /**
     * 获取数据库中强制停止的任务标识列表
     * @return 任务ID
     */
    public static Set<Integer> getForceTaskIdSetFromDB() {
        Set<Integer> forceSet = new HashSet<>();
        //Connection conn = DBConnectionManager.getConnection(1);

        sql = "select id from activetask where status = " + TaskStatus.FORCE.getValue();
        Connection conn = null;
        Statement statement = null;
        ResultSet resultSet = null;
        try {
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();
            resultSet = statement.executeQuery(sql);
            while(resultSet.next()) {
                int id = resultSet.getInt("id");
                forceSet.add(id);
                LOG.debug("从数据库获取强制停止任务[id: " + id + "].");
            }
        }catch(SQLException e) {
            LOG.debug("从数据库中获取强制停止任务异常...");
            e.printStackTrace();
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (resultSet != null) {
                try {
                    resultSet.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
        return forceSet;
    }

    /**
     * 通过任务ID更新任务状态
     * @param taskId  任务标识
     * @param status  待更新状态
     */
    public static void updateActiveTaskStatusByTaskId(Integer taskId, TaskStatus status, Long ts) {
        if (taskId == null || status == null)
            return;

        sql = "update activetask set status = " + status.getValue();
        if (ts != null)
            sql += ",endtime = " + ts;
        sql += " where id = " + taskId;

        Connection conn = null;
        Statement statement = null;
        try {
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();
            statement.executeUpdate(sql);
        }catch (SQLException e) {
            LOG.debug("更新采集任务状态[taskid:" + taskId + "]失败...");
            e.printStackTrace();
        }finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 通过案件ID更新任务状态
     * @param ticketId
     */
    public static void updateTaskStatusByTicketId(Integer ticketId, TaskStatus status) {
        if (ticketId == null || status == null)
            return;

        sql = "update activetask set status = " + status.getValue() + " where ticketid = " + ticketId ;
        Connection conn = null;
        Statement statement = null;
        try {
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();
            statement.executeUpdate(sql);
        } catch (Exception e) {
            LOG.debug("更新数据库采集任务[ticketid: "+ ticketId +"]失败...");
            e.printStackTrace();
        } finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 通过任务更新数据库任务
     * @param task
     */
    public static void updateActiveTaskByTask(ActiveTask task) {
        if (task == null)
            return;

        sql = "update activetask set sensorbytes = " + task.getSensorBytes() + ",sensorpkts = " + task.getSensorpkts() +  " where id = " + task.getId();

        Connection conn = null;
        Statement statement = null;
        try {
            conn = DruidDataSourcePool.getConnection();
            statement = conn.createStatement();
            statement.executeUpdate(sql);
        }catch (SQLException e) {
            LOG.debug("更新数据库采集任务[id:" + task.getId() + "]失败...");
            e.printStackTrace();
        }finally {
            if (statement != null) {
                try {
                    statement.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}