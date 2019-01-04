package cn.edu.jslab6.autoresponse.forensictask;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Created by ffzheng on 2018/6/25.
 */
public class MultiProcessTest {
    public static ExecutorService executorService = Executors.newCachedThreadPool();

    public static void main(String[] args) {
        CountDownLatch countDownLatch = new CountDownLatch(80);
        for (int i = 0; i < 80; i ++) {
            Thre process = new Thre(countDownLatch);
            executorService.execute(process);
        }

        try {
            countDownLatch.await();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        System.out.println("xxxxxxxxxxxxxxxxx");

    }
}
