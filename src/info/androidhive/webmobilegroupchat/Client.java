package info.androidhive.webmobilegroupchat;
 
import java.io.*;
import java.net.Socket;
import java.util.Date;
 
//客户端 ：文件上传下载接口
public class Client extends Socket{
	private final String SERVER_IP="127.0.0.1";
	private final int SERVER_PORT;
	private Socket client;
	private FileInputStream fis;
	private DataOutputStream dos;
	private DataInputStream dis;
	private FileOutputStream fos;
	BufferedWriter bw;
	
	//创建客户端，并指定接收的服务端IP和端口号
	public Client(int port) throws IOException{
		this.SERVER_PORT = port;
		this.client = new Socket(SERVER_IP,SERVER_PORT);
		System.out.println("连接服务端..."+ SERVER_IP + "端口号：" + SERVER_PORT);
	}
 
	//向服务端传输文件(上传文件)
	public void uploadFile(String sendFilePath) throws IOException {
		File file=new File(sendFilePath);
		try {
			fis = new FileInputStream(file);
			dos = new DataOutputStream(client.getOutputStream());//client.getOutputStream()返回此套接字的输出流
			//文件名、大小等属性
//			dos.writeUTF(file.getName());
//			dos.flush();
//			dos.writeLong(file.length());
//			dos.flush();
			 //接收server发送的tag(server中存储文件的路径)
			dis = new DataInputStream(client.getInputStream());
			byte[] fileUrl = new byte[37];
			dis.read(fileUrl, 0, fileUrl.length);
			String url = new String(fileUrl);
			System.out.println("接收到的文件的url:"+ url);
			
			// 开始传输文件
			System.out.println("======== 开始传输文件 ========");
			byte[] bytes = new byte[1024];
			int length = 0;
			
			while ((length = fis.read(bytes, 0, bytes.length)) != -1) {
				dos.write(bytes, 0, length);
				dos.flush();
			}
			
			System.out.println("======== 文件上传传输成功 ========");
			
		}catch(IOException e){
			e.printStackTrace();
			System.out.println("客户端文件传输异常");
		}finally{
			dis.close();
			fis.close();
			dos.close();
		}
	}
	
	public String downloadFile(String recvFileName) throws IOException {
		String createtime ="";
       	String basicPath = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images\\";
		try {		
			 //输出流		
            dos = new DataOutputStream(new BufferedOutputStream(client.getOutputStream()));     
            //发送请求下载的文件  
            byte[] byteArrayFileName = recvFileName.getBytes();
            System.out.println("请求的文件名长度：" + byteArrayFileName.length);
            dos.write(byteArrayFileName, 0, byteArrayFileName.length);   	
            dos.flush();//重要！！！
            
        	//client.shutdownOutput();
        	
			byte[] inputByte = null;
	        int length = 0;
	        dis = new DataInputStream(client.getInputStream());
	        //接收到文件后要写入的文件路径
	        createtime = (new Date()).getTime() +""; 
	        String filePath = basicPath + createtime + ".zip";
	        fos = new FileOutputStream(new File(filePath));
            inputByte = new byte[1024];
            System.out.println("开始接收数据...");
            while ((length = dis.read(inputByte, 0, inputByte.length)) > 0) {
                //System.out.println(length);
                fos.write(inputByte, 0, length);
                fos.flush();
            }
            fos.close();
            System.out.println("完成接收");    
			System.out.println("======== 文件下载成功 ========");
			return  createtime ;
		}catch(IOException e){
			e.printStackTrace();
			System.out.println("客户端文件传输异常");
		}finally{
			dos.close();
			dis.close();
		}	
		return  createtime ;
	}
	
	//上传更新密钥MHOO_UK.txt
		public String uploadUK(String sendFileName) throws IOException {
			String basicPath = "D:\\Development\\apache-tomcat-7.0.94\\webapps\\images\\";
			File file = new File( basicPath + sendFileName);
			String url = "";
			try {
				fis = new FileInputStream(file);
				dos = new DataOutputStream(client.getOutputStream());//client.getOutputStream()返回此套接字的输出流
				//文件名等属性
				byte[] byteArrayFileName = sendFileName.getBytes();
				System.out.println("发送的文件名长度：" + byteArrayFileName.length);
				dos.write(byteArrayFileName, 0, byteArrayFileName.length);

				// 开始传输文件
				System.out.println("======== 开始传输文件 ========");
				byte[] bytes = new byte[1024];
				int length = 0;

				while ((length = fis.read(bytes, 0, bytes.length)) != -1) {
					dos.write(bytes, 0, length);
					dos.flush();
				}
				System.out.println("======== 文件上传传输成功 ========");

				client.shutdownOutput();

				dis = new DataInputStream(client.getInputStream());
				byte[] fileUrl = new byte[10];
				dis.read(fileUrl, 0, 10);
				url = new String(fileUrl);
				System.out.println("接收到的文件的url:"+ url);
				return url;
			}catch(IOException e){
				e.printStackTrace();
				System.out.println("客户端文件传输异常");
			}finally{
				fis.close();
				dis.close();
				dos.close();
			}
			return url;
		}
	
	
//	public static void main(String[] args) {
//		try {
//			Client client1 = new Client(8120); // 启动客户端连接
////			client1.uploadFile("E:\\Program\\eclipse-workplace\\Client\\Files\\photo.zip"); // 上传文件
//			
////			Client client2 = new Client(8121); // 启动客户端连接
////			client2.downloadFile("photo.zip"); //下载文件
//			
////          String test = "photo.zip";
////          System.out.println(System.getProperty("file.encoding"));// java默认编码是UTF-8
////          System.out.println(test);
////          System.out.println(test.length());
////          System.out.println(test.getBytes("GB2312").length);
////          System.out.println(test.getBytes("UTF8").length);
////          System.out.println(test.getBytes("GBK").length);
////          System.out.println(new String(test.getBytes("GB2312"),"GB2312"));//用什么拆就用什么组装，否则显示乱码
////          System.out.println(new String(test.getBytes("GB2312"),"GB2312").length());//用什么拆就用什么组装，否则显示乱码		
//			
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
	
	
}
 