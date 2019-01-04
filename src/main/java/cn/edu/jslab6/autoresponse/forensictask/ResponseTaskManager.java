package cn.edu.jslab6.autoresponse.forensictask;

/**
 * Created by zrwang on 2016/12/12.
 */

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;

/**
 *  保存所有从取证调度模块发送过来的任务(可执行)
 *
 */
public class ResponseTaskManager extends Thread {
    private static final Logger LOG = LoggerFactory.getLogger(ResponseTaskManager.class);

    private ResponseResultSender taskSender = null;
    private volatile boolean isRuning = false;
    private static final int MAX_TASK_NUM = 32;

    private volatile static ArrayBlockingQueue<ResponseTask> execTasks =
            new ArrayBlockingQueue<ResponseTask>(MAX_TASK_NUM);

    public ResponseTaskManager(SystemConfig config) {
        taskSender = new ResponseResultSender(config.getTaskSendUrl());
    }

    static void addUnhandledTask(ResponseTask task) throws InterruptedException {
        execTasks.put(task);
        LOG.debug("Add unhandled response task {}, pending Task size = {}",
                task.getTicketid(), execTasks.size());
    }

    static ResponseTask getExecTask() throws InterruptedException {
        ResponseTask task = execTasks.take();
        LOG.debug("Begin handle response task {}, priority = {}", task.getTicketid(), task.getPriority());
        return task;
    }
}

