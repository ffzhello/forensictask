package cn.edu.jslab6.autoresponse.forensictask;

import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Created by ffzheng on 2017/7/20.
 */
public class ActionHandler {
    private static Logger LOG  = LoggerFactory.getLogger(ActionHandler.class);
    private static SystemConfig systemConfig = new SystemConfig();
    private static ResponseResultSender resultSender = null;

    static {
        try {
            systemConfig = new SystemConfig("./system.properties");
        }catch (IOException e) {
            e.printStackTrace();
        }
        resultSender = new ResponseResultSender(systemConfig.getTaskSendUrl());
    }

    public static void returnResults(ActiveTask activeTask) {
        if (activeTask == null)
            return;

        activeTask.pcapResponseResult = new PcapResponseResult();
        activeTask.pcapResponseResult.ticketid = String.valueOf(activeTask.getTicketId());
        activeTask.pcapResponseResult.actionResult.put(ResponseAction.PcapCap, true);
        activeTask.pcapResponseResult.attach.firstpkttime = activeTask.getFirstpkttime();
        activeTask.pcapResponseResult.attach.lastpkttime = activeTask.getLastpkttime();

        int start = activeTask.getMergedPatFileCount() + 1;
        int end = activeTask.getPatFileCount();

        if (start <= end) {
            for (; start <= end; start ++) {
                String file = activeTask.getDirPath() + "PAT" + String.valueOf(start) + ".pcap";
                byte[] b;
                if ((b = Utils.readBinaryFile(file)) != null) {
                    activeTask.pcapResponseResult.files.fileContent = new String(b, StandardCharsets.ISO_8859_1);
                    if (activeTask.getUsername().equals("CHAIRS")) {
                        String pcapResult = new Gson().toJson(activeTask.pcapResponseResult);
                        try {
                            resultSender.send(pcapResult);
                            LOG.debug("Task[id: " + activeTask.getId() + "] Return " + activeTask.pcapResponseResult.files.fileContent.length() + " bytes packets to CHAIRS success. ");
                        }catch (IOException e) {
                            e.printStackTrace();
                        }
                    } else {
                        //  LOG.debug("Finsh pcap capture, but response task are not from CHAIRS!");
                        LOG.debug("Task[id: " + activeTask.getId() + "] Return " + activeTask.pcapResponseResult.files.fileContent.length() + " bytes packets to OTHERS success. " );
                    }
                }
            }
        }else {
            activeTask.pcapResponseResult.files.fileContent = "";
            if (activeTask.getUsername().equals("CHAIRS")) {
                String pcapResult = new Gson().toJson(activeTask.pcapResponseResult);
                try {
                    resultSender.send(pcapResult);
                    // LOG.debug("Task {} finish pcap capture, ID = {}", task.getTicketId(), task.getId());
                    LOG.debug("Task[id：" + activeTask.getId() + "] Return 0 bytes packets to CHAIRS.");

                }catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                LOG.debug("Task[id: " + activeTask.getId() + "] Return 0 bytes packets to OTHERS.");
            }
        }

        //回送检测结果
        if (activeTask.getUsername().equals("CHAIRS")) {
            // 将IDS相关检测内容封装成ResponseResult格式，发往CHAIRS系统。
            String idsDetectResult = new Gson().toJson(activeTask.responseResult);
            try {
                resultSender.send(idsDetectResult);
            } catch (IOException e) {
                e.printStackTrace();
            }
            LOG.debug("Task[id：" + activeTask.getId() +  "] Return IDS Results to CHAIRS success.");
        } else {
            // FIXME: 不是CHAIRS发送的案件，有需求的话，可以做一些额外的工作。
            LOG.debug("Task[id：" + activeTask.getId() +  "] Return IDS Results to OTHERS success.");
        }

        //初始化内存中任务
        int patCount = activeTask.getPatFileCount();
        activeTask.setMergedPatFileCount(patCount);

        activeTask.setTmpFilename("");
        activeTask.setTmpFileSize(0);
        activeTask.setMegFilename("");

        //更新数据库
        ActiveTaskManager.updateActiveTaskByTask(activeTask);
    }

 /*
 public void forcedTaskDetect(ActiveTask task) {
        if (task == null)
            return;

            String filename = task.getFilename();

            //离线检测
            List<ResponseAction> actions = task.getActionList();
            boolean flag = false;

            try {
                if (actions.contains(ResponseAction.SuricataDetect)) {
                    if (doSuricataDetect(filename, null) == 0)
                        flag = true;
                }
                if (actions.contains(ResponseAction.BroDetect)) {
                    if (doBroDetect(filename, null) == 0)
                        flag = true;
                }
                if (flag == true) {
                    String pDir = new File(filename).getParent();

                    File simpleAlert = new File(pDir,"SimpleAlert" + task.getId() + ".txt");

                    String outPath = simpleAlert.toString();
                    genSimpleAlert(pDir, outPath);
                }
            } catch (InterruptedException e) {
                LOG.debug("任务[id: " + task.getId() + "]离线检测失败...");
                e.printStackTrace();
            }catch (IOException e) {
                LOG.debug("任务[id: " + task.getId() + "]离线检测失败...");
                e.printStackTrace();
        }
    }*/


    //test
    public static void main(String[] args) {

    }
}
