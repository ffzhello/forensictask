package cn.edu.jslab6.autoresponse.forensictask;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Created by zrwang on 2016/12/13.
 */
public class Utils {
    private static final Logger LOG = LoggerFactory.getLogger(Utils.class);

    public static String readFileContent(String filename) {
        StringBuilder sb = new StringBuilder();
        //LOG.debug("For Debug: filename = {}", filename);
        int lineCount = 0;
        try {
            BufferedReader input = new BufferedReader(new FileReader(filename));
            String s;
            try {
                while ((s = input.readLine()) != null) {
                    sb.append(s).append('\n');
                    lineCount++;
                }
            } finally {
                input.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        //LOG.debug("For debug: file has {} lines", lineCount);
        return sb.toString();
    }

    public static byte[] readBinaryFile(String filename) {
        try {
            BufferedInputStream bf = new BufferedInputStream(
                    new FileInputStream(filename));
            //LOG.debug("begin to read file {} to binary", filename);
            try {
                int count = bf.available();
                byte[] data = new byte[count];
                int num = bf.read(data);
                //LOG.debug("read {} bytes, and orig bf.available() = {} bytes.", num, count);
                return data;
            } finally {
                bf.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 拼接两个byte[].
     * @param lhs
     * @param rhs
     * @return
     */
    public static byte[] concatBytes(byte[] lhs, byte[]rhs) {
        byte[] ret = new byte[lhs.length + rhs.length];
        System.arraycopy(lhs, 0, ret, 0, lhs.length);
        System.arraycopy(rhs, 0, ret, lhs.length, rhs.length);
        return ret;
    }

    /**
     * 获取指定目录中(非递归)的所有pcap文件的绝对路径。
     *
     * @param rootdir: 保存pcap文件的目录
     * @return
     */
    public static Iterable<String> getPcapPaths(String rootdir) {
        File path = new File(rootdir);
        String[] pcapPaths;

        pcapPaths = path.list(new FilenameFilter() {
            private Pattern pattern = Pattern.compile(".*\\.pcap");

            public boolean accept(File dir, String name) {
                return pattern.matcher(name).matches();
            }
        });
        Arrays.sort(pcapPaths, String.CASE_INSENSITIVE_ORDER);

        ArrayList<String> pathList = new ArrayList<String>();
        for (String pcapPath : pcapPaths) {
            pathList.add(Paths.get(rootdir, pcapPath).toString());
        }
        return pathList;
    }

    /**
     * 递归删除目录下的所有文件及子目录下所有文件
     * @param dir 将要删除的文件目录
     * @return boolean Returns "true" if all deletions were successful.
     *                 If a deletion fails, the method stops attempting to
     *                 delete and returns "false".
     */
    public static boolean deleteDir(File dir) {
        if (dir.isDirectory()) {
            String[] children = dir.list();
            //递归删除目录中的子目录下
            for (int i = 0; i < children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }
        // 目录此时为空，可以删除
        return dir.delete();
    }

    public static  String listToString(List<String> theList, String sep) {
        StringBuilder sb  = new StringBuilder();
        boolean flag = false;
        for (String t : theList) {
            if (flag) {
                sb.append(sep);
            } else {
                flag = true;
            }
            sb.append(t);
        }
        return sb.toString();
    }

    public static void main(String[] args) {

        File file = new File("E://sss");
        if(file.exists()) {
            File[] files = file.listFiles();
            for (File f: files) {
                String name = f.getName();
                if(name.startsWith("PAT")) {

                    int tPos = name.indexOf('T') + 1;
                    int pPos = name.indexOf('.');
                    String order = name.substring(tPos, pPos);
                    Integer xx = Integer.parseInt(order);

                    System.out.println(xx);
                }else if(name.startsWith("MEG")) {
                     System.out.println(name);
                }else {
                    //del
                    FileManager.deleteFile(f);
                }
            }
        }else {
            System.out.println("nnnn");
        }

       /* BufferedInputStream bufferedInput = null;
        byte[] header = new byte[24];
        byte[] buffer = new byte[24];
        byte[] data ;

        try {

            //创建BufferedInputStream 对象
            bufferedInput = new BufferedInputStream(new FileInputStream("E:/1.txt"));

            boolean isHeader = true;
            int bytesRead = 0;
            int bytesHasRead = 24;

            //从文件中按字节读取内容，到文件尾部时read方法将返回-1
            while ((bytesRead = bufferedInput.read(buffer)) != -1 && bytesHasRead < 80) {
                if (isHeader == true) {
                    System.arraycopy(buffer, 0, header, 0, buffer.length);
                    isHeader = false;
                    buffer = new byte[40];
                }else {
                    bytesHasRead += buffer.length;
                    data = Utils.concatBytes(header, buffer);
                    //将读取的字节转为字符串对象
                    String  chunk = new String(data, 0, bytesRead + 24, StandardCharsets.ISO_8859_1);
                    System.out.println(chunk);
                }
            }
        } catch (FileNotFoundException ex) {
            ex.printStackTrace();
        } catch (IOException ex) {
            ex.printStackTrace();
        } finally {
            //关闭 BufferedInputStream
            try {
                if (bufferedInput != null)
                    bufferedInput.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }*/

    }
}

