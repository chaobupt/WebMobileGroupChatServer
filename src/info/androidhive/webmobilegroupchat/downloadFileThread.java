package info.androidhive.webmobilegroupchat;
import java.io.IOException;

public class downloadFileThread extends Thread {
    private String downfilename;
    private String filename;

    public downloadFileThread(String filename){
        this.downfilename = filename;
    }

    public String getFilename(){
        return filename;
    }
    @Override
    public void run() {
        super.run();
        Client client = null; // 启动客户端连接，下载文件
        try {
            client = new Client(8127);
            filename = client.downloadFile(downfilename);
            
        } catch (IOException e) {
        	try {
				client.close();
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
            e.printStackTrace();
        }
    }
}
